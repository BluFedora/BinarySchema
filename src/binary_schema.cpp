/******************************************************************************/
/*!
 * @file   binary_schema.cpp
 * @author Shareef Raheem (https://blufedora.github.io)
 * @brief
 *   API for a structured binary format to allow for semi-automatic
 *   backwards and forwards data compatibility.
 *
 *   References:
 *     Heavily Inspired By : [https://github.com/RonPieket/StructuredBinary]
 *      Type System Basics : [https://karkare.github.io/cs335/lectures/12TypeSystem.pdf]
 *
 * @copyright Copyright (c) 2022-2023 Shareef Abdoul-Raheem
 */
/******************************************************************************/
#include "binary_schema.hpp"

#include "binaryio/binary_stream.hpp"  // binaryIOAssert, IByteWriter, IByteReader, IOErrorCode

#include "memory/smart_pointer.hpp"  // bfMemMakeShared

#include <algorithm>  // equal
#include <cstring>    // memcmp, memcpy

#if BINARY_SCHEMA_BUILD_VALIDATION
#include <cstdio>  // printf
#endif

#if defined(__GNUC__) || defined(__clang__) || defined(__INTEL_LLVM_COMPILER) || defined(__INTEL_COMPILER)
#define unreachable() __builtin_unreachable()
#elif defined(_MSC_VER)
#define unreachable() __assume(0)
#else
#define unreachable() return binaryIO::IOErrorCode::UnknownError;
#endif

namespace BinarySchema
{
  //
  // ByteCode
  //

  static inline TypeByteCode operator&(const TypeConstructorFlags lhs, const TypeConstructorFlags rhs)
  {
    return std::uint8_t(lhs) & std::uint8_t(rhs);
  }

  static inline bool ByteCodeHasSmallSize(const TypeConstructorFlags byteCode)
  {
    return (byteCode & TypeConstructorFlags::SmallFixedSizeMask) != 0;
  }

  static inline bool IsSmallSize(const ArrayCountType num_elements)
  {
    return num_elements <= ArrayCountType(TypeConstructorFlags::SmallFixedSizeMax);
  }

  static inline TypeConstructorFlags ByteCodeEncodeFlags(TypeConstructorFlags flags, const ArrayCountType num_elements)
  {
    return ((flags & TypeConstructorFlags::FixedSize) && IsSmallSize(num_elements)) ? TypeConstructorFlags(std::uint8_t(flags) | num_elements << std::uint8_t(TypeConstructorFlags::SmallFixedSizeShift)) : flags;
  }

  static inline bool ByteCodeIsDynamicallySized(const TypeConstructorFlags flags)
  {
    return !(flags & TypeConstructorFlags::FixedSize) && !ByteCodeHasSmallSize(flags);
  }

#if BINARY_SCHEMA_BUILD_VALIDATION
#define BINARY_SCHEMA_VERIFY_PRINT(expr, ...) BINARY_SCHEMA_VERIFY_PRINT_((expr), #expr)

  static bool BINARY_SCHEMA_VERIFY_PRINT_(const bool condition, const char* const condition_str)
  {
    if (condition)
    {
      std::fprintf(stderr, "[BinarySchema] Verify failure: %s\n", condition_str);
    }

    return condition;
  }

#else
#define BINARY_SCHEMA_VERIFY_PRINT(...)
#endif

  static inline bool ByteCodeIsConvertCompatible(
   const TypeByteCode* const src,
   const std::uint32_t       num_src_bytes,
   const TypeByteCode* const dst,
   const std::uint32_t       num_dst_bytes)
  {
    std::uint32_t src_byte_code_index = 0u;
    std::uint32_t dst_byte_code_index = 0u;
    while (src_byte_code_index < num_src_bytes && dst_byte_code_index < num_dst_bytes)
    {
      const TypeConstructorFlags src_flags = static_cast<TypeConstructorFlags>(src[src_byte_code_index++]);
      const TypeConstructorFlags dst_flags = static_cast<TypeConstructorFlags>(dst[dst_byte_code_index++]);

      if (ByteCodeIsDynamicallySized(src_flags) && ByteCodeIsDynamicallySized(dst_flags))
      {
        HashStr32 src_hash_str, dst_hash_str;
        std::memcpy(&src_hash_str, src + src_byte_code_index, sizeof(src_hash_str));
        std::memcpy(&dst_hash_str, dst + dst_byte_code_index, sizeof(dst_hash_str));

        if (BINARY_SCHEMA_VERIFY_PRINT(src_hash_str != dst_hash_str))
        {
          return false;
        }
      }

      src_byte_code_index += sizeof(std::uint32_t) * !ByteCodeHasSmallSize(src_flags);
      dst_byte_code_index += sizeof(std::uint32_t) * !ByteCodeHasSmallSize(dst_flags);
    }

    if (BINARY_SCHEMA_VERIFY_PRINT(src_byte_code_index != num_src_bytes) || BINARY_SCHEMA_VERIFY_PRINT(dst_byte_code_index != num_dst_bytes))
    {
      return false;
    }

    return true;
  }

  //
  // Schema Pointer Verification
  //

  static bool VerifyPointer(const void* const pointer, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    if (pointer != nullptr)
    {
      if (BINARY_SCHEMA_VERIFY_PRINT(reinterpret_cast<const unsigned char*>(pointer) < data_block))
      {
        return false;
      }

      if (BINARY_SCHEMA_VERIFY_PRINT(reinterpret_cast<const unsigned char*>(pointer) > (data_block + data_block_size)))
      {
        return false;
      }
    }

    return true;
  }

  template<typename offset_type_t, typename T, std::uint8_t alignment>
  static bool VerifyRelPointer(const binaryIO::rel_ptr<offset_type_t, T, alignment>& pointer, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    return VerifyPointer(pointer.get(), data_block, data_block_size);
  }

  template<typename TCount, typename TPtr>
  static bool VerifyRelArray(const binaryIO::rel_array<TCount, TPtr>& arr, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    return VerifyPointer(arr.begin(), data_block, data_block_size) &&
           VerifyPointer(arr.end(), data_block, data_block_size);
  }

  static bool VerifyTypeByteCode(const SchemaType& type, const binaryIO::rel_array32<TypeByteCode>& byte_code, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    if (!VerifyRelArray(byte_code, data_block, data_block_size))
    {
      return false;
    }

    const TypeByteCode*       byte_code_ptr = byte_code.begin();
    const TypeByteCode* const byte_code_end = byte_code_ptr + byte_code.num_elements;

    while (byte_code_ptr < byte_code_end)
    {
      const TypeConstructorFlags flags = static_cast<TypeConstructorFlags>(*byte_code_ptr++);

      if (!ByteCodeHasSmallSize(flags))
      {
        if (BINARY_SCHEMA_VERIFY_PRINT((byte_code_ptr + sizeof(std::uint32_t)) > byte_code_end))
        {
          return false;
        }

        // Validate dynamic array qualifiers.
        if (ByteCodeIsDynamicallySized(flags))
        {
          HashStr32 member_hash_str;
          std::memcpy(&member_hash_str, byte_code_ptr, sizeof(member_hash_str));

          // The dynamic size must exist and be an unqualified integer type.
          const StructureMember* const dynamic_val = type.FindMember(member_hash_str);
          binaryIOAssert(dynamic_val, "Failed to find dynamic member.");

          if (BINARY_SCHEMA_VERIFY_PRINT(!dynamic_val->base_type))
          {
            return false;
          }

          if (BINARY_SCHEMA_VERIFY_PRINT(!dynamic_val || !dynamic_val->base_type->IsIntScalar() || dynamic_val->HasQualifiers()))
          {
            binaryIOAssert(dynamic_val->base_type->IsIntScalar() && !dynamic_val->HasQualifiers(), "Dynamic member must be an unqualified integer type.");

            return false;
          }
        }

        byte_code_ptr += sizeof(std::uint32_t);
      }
    }

    return byte_code_ptr == byte_code_end;
  }

  static bool VerifyStructureMember(const SchemaType& type, const StructureMember& member, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    return VerifyRelPointer(member.base_type, data_block, data_block_size) && VerifyTypeByteCode(type, member.type_ctors, data_block, data_block_size);
  }

  static bool VerifySchemaType(const SchemaType& type, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    const std::size_t num_members = type.m_Members.size;

    if (!VerifyRelPointer(type.m_Members.keys, data_block, data_block_size) ||
        !VerifyPointer(type.m_Members.keys.get() + num_members, data_block, data_block_size) ||
        !VerifyRelPointer(type.m_Members.values, data_block, data_block_size) ||
        !VerifyPointer(type.m_Members.values.get() + num_members, data_block, data_block_size))
    {
      return false;
    }

    return std::all_of(
     type.m_Members.values.get(),
     type.m_Members.values.get() + num_members,
     [&](const StructureMember& member) -> bool {
       return VerifyStructureMember(type, member, data_block, data_block_size);
     });
  }

  static bool VerifySchemaTypes(const SchemaType* types, const std::uint32_t num_types, const unsigned char* const data_block, const std::uint64_t data_block_size)
  {
    return std::all_of(types, types + num_types, [&](const SchemaType& type) -> bool {
      return VerifySchemaType(type, data_block, data_block_size);
    });
  }

  static bool VerifySchema(const Schema& schema)
  {
    const SchemaHeader& header = schema.header;

    if (BINARY_SCHEMA_VERIFY_PRINT(header.type_id != SchemaHeader::ChunkID))
    {
      return false;
    }

    if (BINARY_SCHEMA_VERIFY_PRINT(header.header_size != sizeof(SchemaHeader)))
    {
      return false;
    }

    return VerifySchemaTypes(schema.Types(), header.num_types, schema.data_bytes.get(), header.data_size);
  }

  //
  // Schema API
  //

  template<typename T>
  static inline bool operator==(const HashStr32Table<T>& lhs, const HashStr32Table<T>& rhs)
  {
    return lhs.size == rhs.size &&
           std::memcmp(lhs.keys.get(), rhs.keys.get(), lhs.size * sizeof(HashStr32)) == 0 &&
           std::equal(lhs.values.get(), lhs.values.get() + lhs.size, rhs.values.get());
  }

  bool operator==(const SchemaType& lhs, const SchemaType& rhs)
  {
    return lhs.m_Size == rhs.m_Size &&
           lhs.m_Alignment == rhs.m_Alignment &&
           lhs.m_Flags == rhs.m_Flags &&
           lhs.m_Members == rhs.m_Members;
  }

  static inline bool operator==(const StructureMember& lhs, const StructureMember& rhs)
  {
    return lhs.offset == rhs.offset &&
           lhs.type_ctors.num_elements == rhs.type_ctors.num_elements &&
           *lhs.base_type == *rhs.base_type &&
           std::memcmp(lhs.type_ctors.begin(), rhs.type_ctors.begin(), lhs.type_ctors.num_elements) == 0;
  }

  bool StructureMember::IsConvertCompatibleWith(const StructureMember& rhs) const noexcept
  {
    return base_type_name == rhs.base_type_name && ByteCodeIsConvertCompatible(
                                                    type_ctors.begin(),
                                                    type_ctors.num_elements,
                                                    rhs.type_ctors.begin(),
                                                    rhs.type_ctors.num_elements);
  }

  StructureMember* SchemaType::FindMember(const HashStr32 name) const
  {
    return m_Members.Find(name);
  }

  const SchemaType* Schema::Types() const
  {
    return reinterpret_cast<const SchemaType*>(data_bytes.get());
  }

  const SchemaType* Schema::FindType(const HashStr32 name) const
  {
    const auto types     = Types();
    const auto types_end = types + header.num_types;

    if (header.flags & SchemaHeader::TypesSorted)
    {
      const auto it = std::lower_bound(types, types_end, name, [](const SchemaType& a, const HashStr32& b) -> bool {
        return a.m_Name.hash < b.hash;
      });

      return (it == types_end || it->m_Name != name) ? nullptr : types + std::distance(types, it);
    }
    else
    {
      const auto it = std::find_if(types, types_end, [name](const SchemaType& type) -> bool {
        return type.m_Name == name;
      });

      return it != types_end ? it : nullptr;
    }
  }

  binaryIO::IOErrorCode Schema::Write(binaryIO::IOStream* const stream) const
  {
    binaryIO::IOErrorCode result = binaryIO::IOErrorCode::Success;

    IOStream_Write(stream, &header, sizeof(SchemaHeader));
    IOStream_Write(stream, data_bytes.get(), header.data_size);

    return stream->error_state;
  }

  std::optional<Schema> Schema::Load(binaryIO::IOStream* const stream, IPolymorphicAllocator& allocator)
  {
    Schema result;
    if (IOStream_Read(stream, &result.header, sizeof(SchemaHeader)).ErrorCode() == binaryIO::IOErrorCode::Success)
    {
      if (result.header.version == SCHEMA_VERSION_INITIAL)
      {
        const size_t         data_bytes_size = result.header.data_size;
        unsigned char* const data_bytes      = bfMemAllocateArray<unsigned char>(allocator, data_bytes_size);

        if (data_bytes != nullptr)
        {
          result.data_bytes = std::shared_ptr<const unsigned char[]>(
           data_bytes,
           [allocator = &allocator, data_bytes_size](unsigned char* const ptr) {
             bfMemDeallocateArray(*allocator, ptr, data_bytes_size);
           },
           Memory::StlAllocator<SchemaType>(allocator));

          if (IOStream_Read(stream, data_bytes, data_bytes_size).ErrorCode() == binaryIO::IOErrorCode::Success)
          {
            if (VerifySchema(result))
            {
              return result;
            }
          }
        }
      }
    }

    return std::nullopt;
  }

  std::optional<Schema> Schema::FromBuffer(const void* const buffer, const std::size_t buffer_size)
  {
    if (buffer_size >= sizeof(SchemaHeader))
    {
      Schema schema;
      std::memcpy(&schema.header, buffer, sizeof(SchemaHeader));  // NOTE(SR): Using memcpy rather than a cast since buffer may not be 8 byte aligned.

      if (buffer_size >= (sizeof(SchemaHeader) + schema.header.data_size))
      {
        const unsigned char* const data_start = reinterpret_cast<const unsigned char*>(buffer) + sizeof(SchemaHeader);

        schema.data_bytes = std::shared_ptr<const unsigned char[]>(data_start, [](const unsigned char* const ptr) {});

        if (VerifySchema(schema))
        {
          return schema;
        }
      }
    }

    return std::nullopt;
  }

  //
  // Builder API
  //

  template<typename T>
  T* SchemaBuilderList<T>::Append(const AllocatorView memory)
  {
    T* const result = bfMemAllocateObject<T>(memory);

    if (result)
    {
      if (tail)
      {
        tail->next = result;
      }
      else
      {
        head = result;
      }
      tail = result;

      ++num_elements;
    }

    return result;
  }

  template<typename T>
  void SchemaBuilderList<T>::Free(const AllocatorView memory)
  {
    T* cursor = head;

    while (cursor)
    {
      T* const next = cursor->next;

      bfMemDeallocateObject(memory, cursor);

      cursor = next;
    }
  }

  const MemberBuilder& MemberBuilder::AddQualifier(TypeConstructorFlags flags_part, std::uint32_t size_part) const
  {
    SchemaBuilderMemberQualifier& qual = *m_Member.qualifiers.Append(m_Allocator);

    qual.flags              = ByteCodeEncodeFlags(flags_part, size_part);
    qual.num_elements.fixed = size_part;

    return *this;
  }

  MemberBuilder TypeBuilder::AddMember(const HashStr32 name, const HashStr32 type_name, const std::size_t offset)
  {
#if BINARY_SCHEMA_BUILD_VALIDATION
    for (SchemaBuilderMemberNode* member = m_Type.members.head; member; member = member->next)
    {
      binaryIOAssert(member->name != name, "Member with this name already exists.");
    }
#endif

    SchemaBuilderMemberNode* const member = m_Type.members.Append(m_Allocator);

    binaryIOAssert(member != nullptr, "Allocation failure.");

    member->name       = name;
    member->base_type  = type_name;
    member->qualifiers = {};
    member->offset     = offset;
    member->next       = nullptr;

    return MemberBuilder{m_Allocator, m_Type, *member};
  }

  void SchemaBuilder::Begin(IPolymorphicAllocator& working_memory)
  {
    ReleaseResources();
    m_NumTypes     = 0u;
    m_Memory       = &working_memory;
    m_TypeListHead = nullptr;
  }

  TypeBuilder SchemaBuilder::AddType(HashStr32 name, std::uint32_t size, std::uint32_t alignment, SchemaTypeFlags flags)
  {
#if BINARY_SCHEMA_BUILD_VALIDATION
    for (SchemaBuilderTypeNode* type = m_TypeListHead; type; type = type->next)
    {
      binaryIOAssert(type->name != name, "Type with this name already exists.");
    }
#endif

    SchemaBuilderTypeNode* const node = bfMemAllocateObject<SchemaBuilderTypeNode>(*m_Memory);

    binaryIOAssert(node != nullptr, "Allocation failure.");

    node->flags     = flags;
    node->name      = name;
    node->size      = size;
    node->alignment = alignment;
    node->members   = {};
    node->next      = nullptr;

    node->next = std::exchange(m_TypeListHead, node);
    ++m_NumTypes;

    return TypeBuilder(*m_Memory, *node);
  }

  static inline std::uint32_t CountByteCodeSize(const SchemaBuilderList<SchemaBuilderMemberQualifier>& qualifiers)
  {
    const SchemaBuilderMemberQualifier* qualifier = qualifiers.head;

    std::uint32_t byte_code_size = qualifiers.num_elements * sizeof(TypeByteCode);

    for (const SchemaBuilderMemberQualifier* qualifier = qualifiers.head; qualifier; qualifier = qualifier->next)
    {
      if (!ByteCodeHasSmallSize(qualifier->flags))
      {
        byte_code_size += sizeof(uint32_t);
      }
    }

    return byte_code_size;
  }

  namespace MergeSortInternal
  {
    template<typename TNode>
    static void SplitList(TNode* list, TNode** out_front, TNode** out_back)
    {
      TNode* fast      = list;
      TNode* slow      = list;
      TNode* front_end = nullptr;

      while (fast && fast->next)
      {
        front_end = slow;
        slow      = slow->next;
        fast      = fast->next->next;
      }

      *out_front = list;
      *out_back  = slow;

      front_end->next = nullptr;
    }

    template<typename TNode, typename Cmp>
    static TNode* SortedMerge(TNode* a, TNode* b, Cmp&& predicate)
    {
      if (!a) { return b; }
      if (!b) { return a; }

      TNode* result = nullptr;

      if (predicate(a, b))
      {
        result       = a;
        result->next = SortedMerge(a->next, b, predicate);
      }
      else
      {
        result       = b;
        result->next = SortedMerge(a, b->next, predicate);
      }

      return result;
    }
  }  // namespace MergeSortInternal

  template<typename TNode, typename Cmp>
  static void MergeSortLinkList(TNode** list_head, Cmp&& predicate)
  {
    TNode* const head = *list_head;

    // Base case of 0 or one items.
    if (head == nullptr || head->next == nullptr)
    {
      return;
    }

    TNode *list_front, *list_back;
    MergeSortInternal::SplitList(head, &list_front, &list_back);

    MergeSortLinkList(&list_front, predicate);
    MergeSortLinkList(&list_back, predicate);

    *list_head = MergeSortInternal::SortedMerge(list_front, list_back, predicate);
  }

  template<typename T>
  static std::size_t GetDynamicMemoryUsage(const std::size_t size)
  {
    static_assert(sizeof(HashStr32Table<T>) == sizeof(std::uint32_t) * 3u, "");

    return (sizeof(HashStr32) + sizeof(T)) * size;
  }

  SchemaBuilderEndToken SchemaBuilder::End(const SchemaHeader::Flags flags)
  {
    if ((flags & SchemaHeader::TypesSorted) != 0u)
    {
      MergeSortLinkList(&m_TypeListHead, [](const SchemaBuilderTypeNode* a, const SchemaBuilderTypeNode* b) {
        return a->name.hash < b->name.hash;
      });
    }

    MemoryRequirements memory_requirements = {};

    memory_requirements.Append<SchemaType>(m_NumTypes);

    for (SchemaBuilderTypeNode* type = m_TypeListHead; type; type = type->next)
    {
      const MemoryIndex num_members = type->members.num_elements;

      memory_requirements.Append<HashStr32>(num_members);
      memory_requirements.Append<StructureMember>(num_members);

      for (const SchemaBuilderMemberNode* member = type->members.head; member; member = member->next)
      {
        memory_requirements.Append<TypeByteCode>(CountByteCodeSize(member->qualifiers));
      }
    }

    return SchemaBuilderEndToken(memory_requirements, flags);
  }

  std::optional<Schema> SchemaBuilder::Build(void* const memory, const SchemaBuilderEndToken& end_token) const
  {
    return BuildInternal(std::shared_ptr<byte[]>(reinterpret_cast<byte*>(memory), [](unsigned char* const) {}), end_token);
  }

  std::optional<Schema> SchemaBuilder::Build(IPolymorphicAllocator& allocator, const SchemaBuilderEndToken& end_token) const
  {
    return BuildInternal(bfMemMakeShared<byte[]>(&allocator, end_token.memory_requirements.size, end_token.memory_requirements.alignment), end_token);
  }

  void BinarySchema::SchemaBuilder::ReleaseResources()
  {
    for (auto type = m_TypeListHead; type != nullptr;)
    {
      for (auto member = type->members.head; member != nullptr; member = member->next)
      {
        member->qualifiers.Free(*m_Memory);
      }

      type->members.Free(*m_Memory);
      bfMemDeallocateObject(*m_Memory, std::exchange(type, type->next));
    }
    m_TypeListHead = nullptr;
  }

  std::optional<Schema> SchemaBuilder::BuildInternal(std::shared_ptr<byte[]>&& data_buffer, const SchemaBuilderEndToken& end_token) const
  {
    byte* bytes_current = data_buffer.get();

    if (bytes_current)
    {
      const MemoryRequirements& memory_requirements = end_token.memory_requirements;

#if BINARY_SCHEMA_BUILD_VALIDATION
      binaryIOAssert(memory_requirements.IsBufferValid(data_buffer.get(), memory_requirements.size), "Data buffer is not properly aligned.");
#endif

      const void* const memory_end = bytes_current + memory_requirements.size;

      const std::uint32_t num_types = m_NumTypes;

      Schema schema{};
      schema.header.type_id   = SchemaHeader::ChunkID;
      schema.header.data_size = memory_requirements.size;
      schema.header.num_types = num_types;
      schema.header.flags     = end_token.schema_flags;
      schema.data_bytes       = std::move(data_buffer);

      SchemaType* const types        = MemoryRequirements::Alloc<SchemaType>(&bytes_current, memory_end, num_types);
      SchemaType*       types_cursor = types;

      for (const SchemaBuilderTypeNode* src_type = m_TypeListHead; src_type; src_type = src_type->next)
      {
        SchemaType* const                      dst_type    = types_cursor++;
        HashStr32Table<StructureMember>* const dst_members = &dst_type->m_Members;

        dst_type->m_Name      = src_type->name;
        dst_type->m_Flags     = src_type->flags;
        dst_type->m_Size      = src_type->size;
        dst_type->m_Alignment = src_type->alignment;
        dst_members->size     = src_type->members.num_elements;
        dst_members->keys     = MemoryRequirements::Alloc<HashStr32>(&bytes_current, memory_end, dst_members->size);
        dst_members->values   = MemoryRequirements::Alloc<StructureMember>(&bytes_current, memory_end, dst_members->size);

        HashStr32*       member_keys_cursor   = dst_members->keys.get();
        StructureMember* member_values_cursor = dst_members->values.get();
        for (const SchemaBuilderMemberNode* src_member = src_type->members.head; src_member; src_member = src_member->next)
        {
          HashStr32* const       dst_key_member = member_keys_cursor++;
          StructureMember* const dst_val_member = member_values_cursor++;

          const std::uint32_t byte_code_size = CountByteCodeSize(src_member->qualifiers);

          *dst_key_member                         = src_member->name;
          dst_val_member->base_type_name          = src_member->base_type;
          dst_val_member->base_type               = nullptr;  // will be patched in second pass.
          dst_val_member->type_ctors.elements     = MemoryRequirements::Alloc<TypeByteCode>(&bytes_current, memory_end, byte_code_size);
          dst_val_member->type_ctors.num_elements = byte_code_size;
          dst_val_member->offset                  = src_member->offset;

          TypeByteCode* byte_code_write_ptr = dst_val_member->type_ctors.begin();

          for (const SchemaBuilderMemberQualifier* qualifier = src_member->qualifiers.head;
               qualifier != nullptr;
               qualifier = qualifier->next)
          {
            *byte_code_write_ptr++ = static_cast<TypeByteCode>(qualifier->flags);

            if (!ByteCodeHasSmallSize(qualifier->flags))
            {
              memcpy(byte_code_write_ptr, &qualifier->num_elements, sizeof(ArrayCountType));
              byte_code_write_ptr += sizeof(ArrayCountType);
            }
          }
        }
      }

      // Patch in member base_type's now that all types registered.
      for (std::size_t type_index = 0u; type_index < num_types; ++type_index)
      {
        const SchemaType& type        = types[type_index];
        const std::size_t num_members = type.m_Members.size;

        for (std::size_t member_index = 0u; member_index < num_members; ++member_index)
        {
          StructureMember& member = type.m_Members.values[member_index];

          member.base_type = schema.FindType(member.base_type_name);
        }
      }

#if BINARY_SCHEMA_BUILD_VALIDATION
      if (VerifySchema(schema))
#endif
        return schema;
    }

    return std::nullopt;
  }

  void AddBasicScalarTypes(SchemaBuilder* const builder)
  {
    static_assert(sizeof(float) == 4u, "This name assumes float is 32bits.");
    static_assert(sizeof(double) == 8u, "This name assumes double is 64bits.");

    builder->AddType<uint8_t>("u8", SchemaTypeFlags::IntegerFlags);
    builder->AddType<uint16_t>("u16", SchemaTypeFlags::IntegerFlags);
    builder->AddType<uint32_t>("u32", SchemaTypeFlags::IntegerFlags);
    builder->AddType<uint64_t>("u64", SchemaTypeFlags::IntegerFlags);
    builder->AddType<int8_t>("i8", SchemaTypeFlags::IntegerFlags);
    builder->AddType<int16_t>("i16", SchemaTypeFlags::IntegerFlags);
    builder->AddType<int32_t>("i32", SchemaTypeFlags::IntegerFlags);
    builder->AddType<int64_t>("i64", SchemaTypeFlags::IntegerFlags);
    builder->AddType<float>("f32", SchemaTypeFlags::FloatingPointFlags);
    builder->AddType<double>("f64", SchemaTypeFlags::FloatingPointFlags);
  }

  //
  // Serialize API
  //

  struct TypeConstructorByteCodeResult
  {
    TypeConstructorFlags flags;
    ArrayCountType       num_elements;
    HashStr32            dyn_member;  // Only valid if: ByteCodeIsDynamicallySized(flags)
  };

  namespace ByteCodeInternal
  {
    namespace detail
    {
      template<typename T>
      static T ReadTypeCtorBytecodeRaw(const TypeByteCode*& type_bytecode)
      {
        T result;
        std::memcpy(&result, std::exchange(type_bytecode, type_bytecode + sizeof(T)), sizeof(T));

        return result;
      }

      static ArrayCountType GetDynamicArrayCount(const StructureMember& dyn_count_member, const void* const parent_object)
      {
        const SchemaType& array_count_type = *dyn_count_member.base_type;

#if BINARY_SCHEMA_RUNTIME_VALIDATION
        binaryIOAssert(array_count_type.IsIntScalar() && !dyn_count_member.HasQualifiers(),
                       "Dynamic array size type must be an unqualified integer type.");
#endif

        const void* const num_elements_data = dyn_count_member.GetMemberData(parent_object);

        std::uint64_t num_elements = 0x0;

        binaryIOAssert(array_count_type.m_Size <= sizeof(num_elements), "Integer type too big.");
        std::memcpy(&num_elements, num_elements_data, array_count_type.m_Size);

        return ArrayCountType(num_elements);
      }
    }  // namespace detail

    template<bool dynamicMemberCanBeNull>
    static TypeConstructorByteCodeResult ReadTypeCtorBytecode(const TypeByteCode*& type_bytecode, const SchemaType& parent_type, const void* const parent_object)
    {
      TypeConstructorByteCodeResult result = {};

      result.flags = detail::ReadTypeCtorBytecodeRaw<TypeConstructorFlags>(type_bytecode);

      if (ByteCodeHasSmallSize(result.flags))
      {
        result.num_elements = (result.flags & TypeConstructorFlags::SmallFixedSizeMask) >> TypeByteCode(TypeConstructorFlags::SmallFixedSizeShift);
      }
      else if (result.flags & TypeConstructorFlags::FixedSize)
      {
        result.num_elements = detail::ReadTypeCtorBytecodeRaw<ArrayCountType>(type_bytecode);
      }
      else
      {
        result.dyn_member = detail::ReadTypeCtorBytecodeRaw<HashStr32>(type_bytecode);

        const StructureMember* const member = parent_type.FindMember(result.dyn_member);

        if constexpr (dynamicMemberCanBeNull)
        {
          // Member can be null when converting from a fixed array to a dynamic array.
          // The int-max(ArrayCountType(-1)) will be clamped by the source data's array count.
          result.num_elements = member ? detail::GetDynamicArrayCount(*member, parent_object) : ArrayCountType(-1);
        }
        else
        {
#if BINARY_SCHEMA_RUNTIME_VALIDATION
          binaryIOAssert(member != nullptr, "Invalid type byte code dynamic size value.");
#endif
          result.num_elements = detail::GetDynamicArrayCount(*member, parent_object);
        }
      }

      return result;
    }

    template<bool dynamicMemberCanBeNull>
    static SizeType GetTypeSize(
     const SchemaType&         parent_type,
     const void* const         parent_object,
     const SchemaType&         base_type,
     const TypeByteCode*       type_bytecode,
     const TypeByteCode* const type_bytecode_end)
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult byte_code = ReadTypeCtorBytecode<dynamicMemberCanBeNull>(type_bytecode, parent_type, parent_object);
        const SizeType                      base_size = (byte_code.flags & TypeConstructorFlags::HeapAllocated) ?
                                                         sizeof(void*) :
                                                         GetTypeSize<false>(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);

        return byte_code.num_elements * base_size;
      }

      return base_type.m_Size;
    }
  }  // namespace ByteCodeInternal

  namespace WriteInternal
  {
    template<ByteOrder byte_order>
    static binaryIO::IOErrorCode WriteUnqualifiedType(binaryIO::IOStream* const stream, const void* const data, const SchemaType& type);

    template<ByteOrder byte_order>
    static binaryIO::IOErrorCode WriteQualifiedType(
     binaryIO::IOStream* const stream,
     const SchemaType&         parent_type,
     const void* const         parent_object,
     const void* const         data,
     const SchemaType&         base_type,
     const TypeByteCode*       type_bytecode,
     const TypeByteCode* const type_bytecode_end)
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult byte_code = ByteCodeInternal::ReadTypeCtorBytecode<false>(type_bytecode, parent_type, parent_object);

        const void* data_location = data;

        if (byte_code.flags & TypeConstructorFlags::HeapAllocated)
        {
          data_location = *static_cast<const void* const*>(data);

          const std::uint8_t is_non_null = data_location ? 1 : 0;
          IOStream_Write(stream, &is_non_null, sizeof(is_non_null));
        }

        if (data_location)
        {
          const SizeType stride = ByteCodeInternal::GetTypeSize<false>(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);

          for (ArrayCountType i = 0u; i < byte_code.num_elements; ++i)
          {
            const void* const element = static_cast<const char*>(data_location) + stride * i;

            WriteQualifiedType<byte_order>(stream, parent_type, parent_object, element, base_type, type_bytecode, type_bytecode_end);
          }
        }
      }
      else
      {
        WriteUnqualifiedType<byte_order>(stream, data, base_type);
      }

      return stream->error_state;
    }

    template<ByteOrder byte_order>
    static binaryIO::IOErrorCode WriteUnqualifiedType(binaryIO::IOStream* const stream, const void* const data, const SchemaType& type)
    {
      if (type.IsTrivial())
      {
        if (type.IsEndianDependent())
        {
          // @ByteOrder
          if constexpr (byte_order == ByteOrder::Native)
          {
            IOStream_Write(stream, data, type.m_Size);
          }
          else if constexpr (byte_order == ByteOrder::LittleEndian)
          {
            switch (type.m_Size)
            {
              case 2u: writeLE(stream, *static_cast<const std::uint16_t*>(data)); break;
              case 4u: writeLE(stream, *static_cast<const std::uint32_t*>(data)); break;
              case 8u: writeLE(stream, *static_cast<const std::uint64_t*>(data)); break;
              default: unreachable();
            }
          }
          else if constexpr (byte_order == ByteOrder::BigEndian)
          {
            switch (type.m_Size)
            {
              case 2u: writeBE(stream, *static_cast<const std::uint16_t*>(data)); break;
              case 4u: writeBE(stream, *static_cast<const std::uint32_t*>(data)); break;
              case 8u: writeBE(stream, *static_cast<const std::uint64_t*>(data)); break;
              default: unreachable();
            }
          }
        }
        else
        {
          IOStream_Write(stream, data, type.m_Size);
        }
      }
      else
      {
        type.m_Members.ForEach([&](const BinarySchema::HashStr32 member_name, const BinarySchema::StructureMember& member) {
          WriteQualifiedType<byte_order>(
           stream,
           type,
           data,
           member.GetMemberData(data),
           *member.base_type,
           member.type_ctors.begin(),
           member.type_ctors.end());
        });
      }

      return stream->error_state;
    }
  }  // namespace WriteInternal

  binaryIO::IOErrorCode Write(binaryIO::IOStream* const stream,
                              const SchemaType&         type,
                              const void* const         data,
                              const ByteOrder           byte_order)
  {
    // @ByteOrder
    switch (byte_order)
    {
      case ByteOrder::Native: return WriteInternal::WriteUnqualifiedType<ByteOrder::Native>(stream, data, type);
      case ByteOrder::LittleEndian: return WriteInternal::WriteUnqualifiedType<ByteOrder::LittleEndian>(stream, data, type);
      case ByteOrder::BigEndian: return WriteInternal::WriteUnqualifiedType<ByteOrder::BigEndian>(stream, data, type);
      default: unreachable();
    }
  }

  binaryIO::IOErrorCode Write(binaryIO::IOStream* const stream,
                              const Schema&             schema,
                              const HashStr32           type_name,
                              const void* const         data,
                              const ByteOrder           byte_order)
  {
    const SchemaType* const type = schema.FindType(type_name);

#if BINARY_SCHEMA_RUNTIME_VALIDATION
    binaryIOAssert(type != nullptr, "Failed to find type.");
#endif

    return Write(stream, *type, data, byte_order);
  }

  namespace ReadInternal
  {
    template<ByteOrder byte_order>
    static binaryIO::IOErrorCode ReadUnqualifiedType(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, void* const data, const SchemaType& type);

    template<ByteOrder byte_order>
    static binaryIO::IOErrorCode ReadQualifiedType(
     binaryIO::IOStream* const stream,
     IPolymorphicAllocator&    memory,
     const SchemaType&         parent_type,
     const void* const         parent_object,
     void* const               data,
     const SchemaType&         base_type,
     const TypeByteCode*       type_bytecode,
     const TypeByteCode* const type_bytecode_end)
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult byte_code    = ByteCodeInternal::ReadTypeCtorBytecode<false>(type_bytecode, parent_type, parent_object);
        const ArrayCountType                num_elements = byte_code.num_elements;
        const SizeType                      stride       = ByteCodeInternal::GetTypeSize<false>(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);

        void* write_location = data;

        if (byte_code.flags & TypeConstructorFlags::HeapAllocated)
        {
          std::uint8_t                is_non_null;
          const binaryIO::IOErrorCode io_result = IOStream_Read(stream, &is_non_null, sizeof(is_non_null)).ErrorCode();

          if (io_result != binaryIO::IOErrorCode::Success)
          {
            is_non_null = false;
          }

          write_location                  = is_non_null ? bfMemAllocate(memory, num_elements * stride, base_type.m_Alignment) : (void*)nullptr;
          *reinterpret_cast<void**>(data) = write_location;
        }

        if (write_location)
        {
          for (ArrayCountType i = 0u; i < num_elements; ++i)
          {
            void* const element = static_cast<char*>(write_location) + stride * i;

            ReadQualifiedType<byte_order>(stream, memory, parent_type, parent_object, element, base_type, type_bytecode, type_bytecode_end);
          }
        }
      }
      else
      {
        ReadUnqualifiedType<byte_order>(stream, memory, data, base_type);
      }

      return stream->error_state;
    }

    template<ByteOrder byte_order>
    static binaryIO::IOErrorCode ReadUnqualifiedType(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, void* const data, const SchemaType& type)
    {
      if (type.IsTrivial())
      {
        if (type.IsEndianDependent())
        {
          // @ByteOrder
          if constexpr (byte_order == ByteOrder::Native)
          {
            IOStream_Read(stream, data, type.m_Size);
          }
          else if constexpr (byte_order == ByteOrder::LittleEndian)
          {
            switch (type.m_Size)
            {
              case 2u: readLE(stream, static_cast<std::uint16_t*>(data)); break;
              case 4u: readLE(stream, static_cast<std::uint32_t*>(data)); break;
              case 8u: readLE(stream, static_cast<std::uint64_t*>(data)); break;
              default: unreachable();
            }
          }
          else if constexpr (byte_order == ByteOrder::BigEndian)
          {
            switch (type.m_Size)
            {
              case 2u: readBE(stream, static_cast<std::uint16_t*>(data)); break;
              case 4u: readBE(stream, static_cast<std::uint32_t*>(data)); break;
              case 8u: readBE(stream, static_cast<std::uint64_t*>(data)); break;
              default: unreachable();
            }
          }
        }
        else
        {
          IOStream_Read(stream, data, type.m_Size);
        }
      }
      else
      {
        type.m_Members.ForEach([&](const BinarySchema::HashStr32 member_name, const BinarySchema::StructureMember& member) {
          ReadQualifiedType<byte_order>(
           stream,
           memory,
           type,
           data,
           member.GetMemberData(data),
           *member.base_type,
           member.type_ctors.begin(),
           member.type_ctors.end());
        });
      }

      return stream->error_state;
    }
  }  // namespace ReadInternal

  binaryIO::IOErrorCode Read(binaryIO::IOStream* const stream,
                             IPolymorphicAllocator&    memory,
                             const SchemaType&         type,
                             void* const               data,
                             const ByteOrder           byte_order)
  {
    // @ByteOrder
    switch (byte_order)
    {
      case ByteOrder::Native: return ReadInternal::ReadUnqualifiedType<ByteOrder::Native>(stream, memory, data, type);
      case ByteOrder::LittleEndian: return ReadInternal::ReadUnqualifiedType<ByteOrder::LittleEndian>(stream, memory, data, type);
      case ByteOrder::BigEndian: return ReadInternal::ReadUnqualifiedType<ByteOrder::BigEndian>(stream, memory, data, type);
      default: unreachable();
    }
  }

  binaryIO::IOErrorCode Read(binaryIO::IOStream* const stream,
                             IPolymorphicAllocator&    memory,
                             const Schema&             schema,
                             const HashStr32           type_name,
                             void* const               data,
                             const ByteOrder           byte_order)
  {
    const SchemaType* const type = schema.FindType(type_name);

#if BINARY_SCHEMA_RUNTIME_VALIDATION
    binaryIOAssert(type != nullptr, "Failed to find type.");
#endif

    return Read(stream, memory, *type, data, byte_order);
  }

  namespace ConvertInternal
  {
    static void ConvertUnqualifiedType(IPolymorphicAllocator& dst_memory,
                                       const void* const      src_data,
                                       void* const            dst_data,
                                       const SchemaType&      src_type,
                                       const SchemaType&      dst_type);

    static void ConvertQualifiedType(const SchemaType&         src_parent_type,
                                     const void* const         src_parent_object,
                                     const SchemaType&         src_type,
                                     const void* const         src_object,
                                     const SchemaType&         dst_parent_type,
                                     void* const               dst_parent_object,
                                     const SchemaType&         dst_type,
                                     void* const               dst_object,
                                     IPolymorphicAllocator&    dst_memory,
                                     const TypeByteCode*       type_bytecode,
                                     const TypeByteCode* const type_bytecode_end,
                                     const TypeByteCode*       dst_type_bytecode)
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult src_byte_code     = ByteCodeInternal::ReadTypeCtorBytecode<false>(type_bytecode, src_parent_type, src_parent_object);
        const TypeConstructorByteCodeResult dst_byte_code     = ByteCodeInternal::ReadTypeCtorBytecode<true>(dst_type_bytecode, src_parent_type, src_parent_object);
        const TypeConstructorFlags          src_type_flags    = src_byte_code.flags;
        const TypeConstructorFlags          dst_type_flags    = dst_byte_code.flags;
        const ArrayCountType                num_data_elements = std::min(src_byte_code.num_elements, dst_byte_code.num_elements);
        const SizeType                      src_stride        = ByteCodeInternal::GetTypeSize<false>(src_parent_type, src_parent_object, src_type, type_bytecode, type_bytecode_end);
        const SizeType                      dst_stride        = ByteCodeInternal::GetTypeSize<true>(src_parent_type, src_parent_object, dst_type, type_bytecode, type_bytecode_end);

        // Patchwork if converting from a fixed size to a dynamic size.
        // Writes the number of elements to the dynamic member field.
        if (!ByteCodeIsDynamicallySized(src_type_flags) && ByteCodeIsDynamicallySized(dst_type_flags))
        {
#if BINARY_SCHEMA_RUNTIME_VALIDATION
          binaryIOAssert(!src_parent_type.FindMember(dst_byte_code.dyn_member), "This field should not be in source schema, it would get overridden to a potentially incorrect value.");
#endif

          const StructureMember* const dst_dyn_member = dst_parent_type.FindMember(dst_byte_code.dyn_member);

#if BINARY_SCHEMA_RUNTIME_VALIDATION
          binaryIOAssert(dst_dyn_member, "Failed to find dynamic member.");
          binaryIOAssert(dst_dyn_member->base_type->IsIntScalar() && !dst_dyn_member->HasQualifiers(), "Dynamic member must be an unqualified integer type.");
#endif

          void* const    num_elements_data = dst_dyn_member->GetMemberData(dst_parent_object);
          const SizeType num_elements_size = dst_dyn_member->base_type->m_Size;

          std::memset(num_elements_data, 0x0, num_elements_size);
          std::memcpy(num_elements_data, &num_data_elements, std::min(num_elements_size, SizeType(sizeof(num_data_elements))));
        }

        const void* read_location  = src_object;
        void*       write_location = dst_object;

        if (src_type_flags & TypeConstructorFlags::HeapAllocated)
        {
          read_location = *static_cast<const void* const*>(src_object);
        }

        if (dst_type_flags & TypeConstructorFlags::HeapAllocated)
        {
          const bool is_fixed_size = dst_type_flags & TypeConstructorFlags::FixedSize;  // Fixed sized heap array are expected to always be a certain size.

          write_location = read_location ? bfMemAllocate(dst_memory, (is_fixed_size ? dst_byte_code.num_elements : num_data_elements) * dst_stride, dst_type.m_Alignment) : (void*)nullptr;

          *reinterpret_cast<void**>(dst_object) = write_location;
        }

        if (read_location && write_location)
        {
          for (ArrayCountType i = 0u; i < num_data_elements; ++i)
          {
            const void* const read_element  = static_cast<const char*>(read_location) + src_stride * i;
            void* const       write_element = static_cast<char*>(write_location) + dst_stride * i;

            ConvertQualifiedType(
             src_parent_type,
             src_parent_object,
             src_type,
             read_element,
             dst_parent_type,
             dst_parent_object,
             dst_type,
             write_element,
             dst_memory,
             type_bytecode,
             type_bytecode_end,
             dst_type_bytecode);
          }
        }
      }
      else
      {
        ConvertUnqualifiedType(dst_memory, src_object, dst_object, src_type, dst_type);
      }
    }

    static void ConvertUnqualifiedType(IPolymorphicAllocator& dst_memory,
                                       const void* const      src_data,
                                       void* const            dst_data,
                                       const SchemaType&      src_type,
                                       const SchemaType&      dst_type)
    {
      if (src_type.IsTrivial() && src_type == dst_type)
      {
        std::memcpy(dst_data, src_data, src_type.m_Size);
      }
      else
      {
        dst_type.m_Members.ForEach([&](HashStr32 member_name, const StructureMember& dst_member) {
          const StructureMember* const src_member = src_type.FindMember(member_name);

          if (src_member && src_member->IsConvertCompatibleWith(dst_member))
          {
            ConvertQualifiedType(
             src_type,
             src_data,
             *src_member->base_type,
             src_member->GetMemberData(src_data),
             dst_type,
             dst_data,
             *dst_member.base_type,
             dst_member.GetMemberData(dst_data),
             dst_memory,
             src_member->type_ctors.begin(),
             src_member->type_ctors.end(),
             dst_member.type_ctors.begin());
          }
        });
      }
    }
  }  // namespace ConvertInternal

  void Convert(const void* const      src_struct,
               const SchemaType&      src_type,
               void* const            dst_struct,
               const SchemaType&      dst_type,
               IPolymorphicAllocator& dst_memory)
  {
    return ConvertInternal::ConvertUnqualifiedType(dst_memory, src_struct, dst_struct, src_type, dst_type);
  }

  void Convert(const void* const      src_struct,
               const Schema&          src_schema,
               void* const            dst_struct,
               const Schema&          dst_schema,
               IPolymorphicAllocator& dst_memory,
               HashStr32              type_name)
  {
    const SchemaType* const src_type = src_schema.FindType(type_name);
    const SchemaType* const dst_type = dst_schema.FindType(type_name);

#if BINARY_SCHEMA_RUNTIME_VALIDATION
    binaryIOAssert(src_type != nullptr, "Failed to find source type.");
    binaryIOAssert(dst_type != nullptr, "Failed to find destination type.");
#endif

    return Convert(src_struct, *src_type, dst_struct, *dst_type, dst_memory);
  }

  binaryIO::IOErrorCode Upgrade(binaryIO::IOStream* const stream,
                                IPolymorphicAllocator&    memory,
                                const SchemaType&         src_type,
                                const SchemaType&         dst_type,
                                void* const               dst_struct,
                                const ByteOrder           byte_order)
  {
    if (src_type == dst_type)
    {
      return Read(stream, memory, dst_type, dst_struct, byte_order);
    }
    else
    {
      const AllocationResult src_struct_allocation = bfMemAllocate(memory, src_type.m_Size, src_type.m_Alignment);

      if (!src_struct_allocation)
      {
        return binaryIO::IOErrorCode::AllocationFailure;
      }

      void* const                 src_struct  = src_struct_allocation.ptr;
      const binaryIO::IOErrorCode read_result = Read(stream, memory, src_type, src_struct, byte_order);

      if (read_result == binaryIO::IOErrorCode::Success)
      {
        Convert(src_struct, src_type, dst_struct, dst_type, memory);
      }

      BinarySchema::FreeDynamicMemory(memory, src_type, src_struct);
      bfMemDeallocate(memory, src_struct_allocation.ptr, src_struct_allocation.num_bytes, src_type.m_Alignment);
      return read_result;
    }
  }

  binaryIO::IOErrorCode Upgrade(binaryIO::IOStream* const stream,
                                IPolymorphicAllocator&    memory,
                                const Schema&             src_schema,
                                const Schema&             dst_schema,
                                void* const               dst_struct,
                                const HashStr32           type_name,
                                const ByteOrder           byte_order)
  {
    const SchemaType* const src_type = src_schema.FindType(type_name);
    const SchemaType* const dst_type = dst_schema.FindType(type_name);

#if BINARY_SCHEMA_RUNTIME_VALIDATION
    binaryIOAssert(src_type != nullptr, "Failed to find source type.");
    binaryIOAssert(dst_type != nullptr, "Failed to find destination type.");
#endif

    return Upgrade(stream, memory, *src_type, *dst_type, dst_struct, byte_order);
  }

  namespace FreeInternal
  {
    static void FreeUnqualifiedType(IPolymorphicAllocator& memory, void* const data, const SchemaType& type);

    static void FreeQualifiedType(
     IPolymorphicAllocator&    memory,
     const SchemaType&         parent_type,
     const void* const         parent_object,
     void* const               data,
     const SchemaType&         base_type,
     const TypeByteCode*       type_bytecode,
     const TypeByteCode* const type_bytecode_end)
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult byte_code         = ByteCodeInternal::ReadTypeCtorBytecode<false>(type_bytecode, parent_type, parent_object);
        const bool                          is_heap_allocated = byte_code.flags & TypeConstructorFlags::HeapAllocated;
        void* const                         data_location     = is_heap_allocated ? *static_cast<void* const*>(data) : data;

        if (data_location)
        {
          const SizeType       stride       = ByteCodeInternal::GetTypeSize<false>(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);
          const ArrayCountType num_elements = byte_code.num_elements;

          for (ArrayCountType i = 0u; i < num_elements; ++i)
          {
            void* const element = static_cast<char*>(data_location) + stride * i;

            FreeQualifiedType(memory, parent_type, parent_object, element, base_type, type_bytecode, type_bytecode_end);
          }

          if (is_heap_allocated)
          {
            bfMemDeallocate(memory, data_location, num_elements * stride, base_type.m_Alignment);
          }
        }
      }
      else
      {
        FreeUnqualifiedType(memory, data, base_type);
      }
    }

    static void FreeUnqualifiedType(IPolymorphicAllocator& memory, void* const data, const SchemaType& type)
    {
      type.m_Members.ForEach([&](const BinarySchema::HashStr32 member_name, const BinarySchema::StructureMember& member) {
        FreeQualifiedType(
         memory,
         type,
         data,
         member.GetMemberData(data),
         *member.base_type,
         member.type_ctors.begin(),
         member.type_ctors.end());
      });
    }
  }  // namespace FreeInternal

  void FreeDynamicMemory(IPolymorphicAllocator& memory, const SchemaType& type, void* const data)
  {
    FreeInternal::FreeUnqualifiedType(memory, data, type);
  }

  void FreeDynamicMemory(IPolymorphicAllocator& memory, const Schema& schema, const HashStr32 type_name, void* const data)
  {
    const SchemaType* const type = schema.FindType(type_name);

#if BINARY_SCHEMA_RUNTIME_VALIDATION
    binaryIOAssert(type != nullptr, "Failed to find type.");
#endif

    return FreeDynamicMemory(memory, *type, data);
  }
}  // namespace BinarySchema

#undef unreachable

/******************************************************************************/
/*
  MIT License

  Copyright (c) 2022-2023 Shareef Abdoul-Raheem

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/
/******************************************************************************/
