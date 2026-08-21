/******************************************************************************/
/*!
 * @file   binary_schema.cpp
 * @author Shareef Raheem (https://blufedora.github.io)
 * @brief
 *   API for a structured binary format to allow for semi-automatic
 *   backwards and forwards data compatibility.
 *
 *   References:
 *     [Developing Imperfect Software by Ron Pieket](https://media.gdcvault.com/gdc2012/slides/Programming%20Track/Pieket_Developing_Imperfect_Software.pdf) (Local Copy: presentations/Pieket_Developing_Imperfect_Software.pdf)
 *      Type System Basics : [https://karkare.github.io/cs335/lectures/12TypeSystem.pdf]
 *
 * @copyright Copyright (c) 2022-2026 Shareef Abdoul-Raheem
 */
/******************************************************************************/
#include "binary_schema.hpp"

#include "binaryio/binary_stream.hpp"  // binaryIOAssert, IByteWriter, IByteReader, IOErrorCode

#include <algorithm>  // equal
#include <cstring>    // memcmp, memcpy

#if BINARY_SCHEMA_BUILD_VALIDATION
#include <cstdio>  // printf
#endif

namespace BinarySchema
{
  // ByteCode //

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

  static inline std::uint32_t DynamicSize_GetOffset(const DynamicSize dynamic_size)
  {
    return (std::uint32_t(dynamic_size) >> std::uint32_t(DynamicSize::OffsetShift));
  }

  static inline std::uint32_t DynamicSize_GetSize(const DynamicSize dynamic_size)
  {
    switch (DynamicSize(std::uint32_t(dynamic_size) & std::uint32_t(DynamicSize::SizeClassMask)))
    {
      case DynamicSize::Int8:  return sizeof(std::uint8_t);
      case DynamicSize::Int16: return sizeof(std::uint16_t);
      case DynamicSize::Int32: return sizeof(std::uint32_t);
      case DynamicSize::Int64: return sizeof(std::uint64_t);
      default:                 return 0;
    }
  }

  static inline bool DynamicSize_IsSigned(const DynamicSize dynamic_size)
  {
    return (std::uint32_t(dynamic_size) & std::uint32_t(DynamicSize::Signed)) != 0x0;
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

  inline static bool ByteCodeIsConvertCompatible(const TypeByteCode* const src, const std::uint32_t num_src_bytes, const TypeByteCode* const dst, const std::uint32_t num_dst_bytes)
  {
    std::uint32_t src_byte_code_index = 0u;
    std::uint32_t dst_byte_code_index = 0u;
    while (src_byte_code_index < num_src_bytes && dst_byte_code_index < num_dst_bytes)
    {
      const TypeConstructorFlags src_flags = static_cast<TypeConstructorFlags>(src[src_byte_code_index++]);
      const TypeConstructorFlags dst_flags = static_cast<TypeConstructorFlags>(dst[dst_byte_code_index++]);

      if (ByteCodeIsDynamicallySized(src_flags) && ByteCodeIsDynamicallySized(dst_flags))
      {
        DynamicSize src_hash_str, dst_hash_str;
        std::memcpy(&src_hash_str, src + src_byte_code_index, sizeof(src_hash_str));
        std::memcpy(&dst_hash_str, dst + dst_byte_code_index, sizeof(dst_hash_str));

        if (src_hash_str != dst_hash_str)
        {
          return false;
        }
      }

      src_byte_code_index += sizeof(std::uint32_t) * !ByteCodeHasSmallSize(src_flags);
      dst_byte_code_index += sizeof(std::uint32_t) * !ByteCodeHasSmallSize(dst_flags);
    }

    if ((src_byte_code_index != num_src_bytes) || (dst_byte_code_index != num_dst_bytes))
    {
      return false;
    }

    return true;
  }

  //
  // Schema Pointer Verification
  //

  static bool VerifyPointer(const void* const pointer, const void* const data_block, const std::uint64_t data_block_size)
  {
    if (pointer != nullptr)
    {
      if (BINARY_SCHEMA_VERIFY_PRINT(static_cast<const byte*>(pointer) < static_cast<const byte*>(data_block)))
      {
        return false;
      }

      if (BINARY_SCHEMA_VERIFY_PRINT(static_cast<const byte*>(pointer) > (static_cast<const byte*>(data_block) + data_block_size)))
      {
        return false;
      }
    }

    return true;
  }

  template<typename offset_type_t, typename T, std::uint8_t alignment>
  static bool VerifyRelPointer(const binaryIO::rel_ptr<offset_type_t, T, alignment>& pointer, const void* const data_block, const std::uint64_t data_block_size)
  {
    return VerifyPointer(pointer.get(), data_block, data_block_size);
  }

  template<typename TCount, typename TPtr>
  static bool VerifyRelArray(const binaryIO::rel_array<TCount, TPtr>& arr, const void* const data_block, const std::uint64_t data_block_size)
  {
    return VerifyPointer(arr.begin(), data_block, data_block_size) &&
           VerifyPointer(arr.end(), data_block, data_block_size);
  }

  static bool VerifyTypeByteCode(const SchemaType& type, const binaryIO::rel_array32<TypeByteCode>& byte_code, const void* const data_block, const std::uint64_t data_block_size)
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

        if (ByteCodeIsDynamicallySized(flags))
        {
          DynamicSize dynamic_size;
          std::memcpy(&dynamic_size, byte_code_ptr, sizeof(dynamic_size));

          const std::uint32_t offset = DynamicSize_GetOffset(dynamic_size);

          if (BINARY_SCHEMA_VERIFY_PRINT(offset >= type.m_Size))
          {
            return false;
          }
        }

        byte_code_ptr += sizeof(std::uint32_t);
      }
    }

    return byte_code_ptr == byte_code_end;
  }

  static bool VerifyStructureMember(const SchemaType& type, const StructureMember& member, const void* const data_block, const std::uint64_t data_block_size)
  {
    if (BINARY_SCHEMA_VERIFY_PRINT(member.base_type.get() == nullptr))
    {
      return false;
    }

    return VerifyRelPointer(member.base_type, data_block, data_block_size) &&
           VerifyTypeByteCode(type, member.type_ctors, data_block, data_block_size);
  }

  static bool VerifySchemaType(const SchemaType& type, const void* const data_block, const std::uint64_t data_block_size)
  {
    if (!VerifyRelPointer(type.m_Name.debug_name, data_block, data_block_size))
    {
      return false;
    }

    if (!VerifyRelArray(type.m_Members, data_block, data_block_size))
    {
      return false;
    }

    return std::all_of(
     type.m_Members.begin(),
     type.m_Members.end(),
     [&](const StructureMember& member) -> bool {
       return VerifyStructureMember(type, member, data_block, data_block_size);
     });
  }

  static bool VerifySchemaTypes(const SchemaType* types, const std::uint64_t num_types, const void* const data_block, const std::uint64_t data_block_size)
  {
    return std::all_of(types, types + num_types, [&](const SchemaType& type) -> bool {
      return VerifySchemaType(type, data_block, data_block_size);
    });
  }

  static bool VerifySchema(const Schema& schema)
  {
    if (BINARY_SCHEMA_VERIFY_PRINT(schema.type_id != SchemaHeader::ChunkID))
    {
      return false;
    }

    if (BINARY_SCHEMA_VERIFY_PRINT(schema.header_size != sizeof(SchemaHeader)))
    {
      return false;
    }

    return VerifySchemaTypes(schema.types.get(), schema.num_types, schema.types.get(), schema.data_size);
  }

  //
  // Schema API
  //

  bool operator==(const SchemaType& lhs, const SchemaType& rhs)
  {
    return lhs.m_Size == rhs.m_Size &&
           lhs.m_Alignment == rhs.m_Alignment &&
           lhs.m_Flags == rhs.m_Flags &&
           std::memcmp(lhs.m_Members.begin(), rhs.m_Members.begin(), lhs.m_Members.num_elements) == 0;
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
    return base_type == rhs.base_type && ByteCodeIsConvertCompatible(
                                          type_ctors.begin(),
                                          type_ctors.num_elements,
                                          rhs.type_ctors.begin(),
                                          rhs.type_ctors.num_elements);
  }

  const StructureMember* SchemaType::FindMember(const HashStr32 name) const
  {
    for (const StructureMember& member : m_Members)
    {
      if (member.name.hash == name.hash)
      {
        return &member;
      }
    }

    return nullptr;
  }

  const SchemaType* Schema::FindType(const HashStr32 name) const
  {
    const auto types     = this->types.get();
    const auto types_end = types + num_types;
    const auto it        = std::lower_bound(types, types_end, name, [](const SchemaType& a, const HashStr32& b) -> bool { return a.m_Name.hash < b.hash; });

    return (it == types_end || it->m_Name.hash != name.hash) ? nullptr : types + std::distance(types, it);
  }

  //
  // Serialize API
  //

  struct TypeConstructorByteCodeResult
  {
    TypeConstructorFlags flags;
    ArrayCountType       num_elements;
    DynamicSize          dyn_size;  // Only valid if: ByteCodeIsDynamicallySized(flags)
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

      static ArrayCountType GetDynamicArrayCount(const DynamicSize dynamic_size, const void* const parent_object)
      {
        const std::uint32_t byte_offset       = DynamicSize_GetOffset(dynamic_size);
        const std::uint32_t integer_size      = DynamicSize_GetSize(dynamic_size);
        const void* const   num_elements_data = reinterpret_cast<const byte*>(parent_object) + byte_offset;

        std::uint64_t num_elements = 0x0;
        std::memcpy(&num_elements, num_elements_data, integer_size);

        if (DynamicSize_IsSigned(dynamic_size))
        {
          if ((num_elements >> ((CHAR_BIT * integer_size) - 1)) != 0)  // Clamp negative numbers to zero.
          {
            return 0;
          }
        }

        return ArrayCountType(num_elements);
      }
    }  // namespace detail

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
        result.dyn_size     = detail::ReadTypeCtorBytecodeRaw<DynamicSize>(type_bytecode);
        result.num_elements = detail::GetDynamicArrayCount(result.dyn_size, parent_object);
      }

      return result;
    }

    static SizeType GetTypeSize(const SchemaType& parent_type, const void* const parent_object, const SchemaType& base_type, const TypeByteCode* type_bytecode, const TypeByteCode* const type_bytecode_end)
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult byte_code = ReadTypeCtorBytecode(type_bytecode, parent_type, parent_object);
        const SizeType                      base_size = (byte_code.flags & TypeConstructorFlags::HeapAllocated) ?
                                                         sizeof(void*) :
                                                         GetTypeSize(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);

        return byte_code.num_elements * base_size;
      }
      else
      {
        return base_type.m_Size;
      }
    }
  }  // namespace ByteCodeInternal

  namespace WriteInternal
  {
    static binaryIO::IOErrorCode WriteUnqualifiedType(binaryIO::IOStream* const stream, const void* const data, const SchemaType& type);

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
        const TypeConstructorByteCodeResult byte_code = ByteCodeInternal::ReadTypeCtorBytecode(type_bytecode, parent_type, parent_object);

        const void* data_location = data;

        if (byte_code.flags & TypeConstructorFlags::HeapAllocated)
        {
          data_location = *static_cast<const void* const*>(data);

          const std::uint8_t is_non_null = data_location ? 1 : 0;
          IOStream_Write(stream, &is_non_null, sizeof(is_non_null));
        }

        if (data_location != nullptr)
        {
          const SizeType stride = ByteCodeInternal::GetTypeSize(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);

          for (ArrayCountType i = 0u; i < byte_code.num_elements; ++i)
          {
            const void* const element = static_cast<const char*>(data_location) + stride * i;

            WriteQualifiedType(stream, parent_type, parent_object, element, base_type, type_bytecode, type_bytecode_end);
          }
        }
      }
      else
      {
        WriteUnqualifiedType(stream, data, base_type);
      }

      return stream->error_state;
    }

    template<typename T>
    static void WriteLE(binaryIO::IOStream* const stream, const void* const data)
    {
      static_assert(std::is_integral_v<T>, "Expected to be an integer type.");

      binaryIO::writeLE(stream, *static_cast<const T*>(data));
    }

    static binaryIO::IOErrorCode WriteUnqualifiedType(binaryIO::IOStream* const stream, const void* const data, const SchemaType& type)
    {
      if (type.IsScalar())
      {
        switch (type.m_Size)
        {
          case sizeof(std::uint8_t):
            WriteLE<std::uint8_t>(stream, data);
            break;
          case sizeof(std::uint16_t):
            WriteLE<std::uint16_t>(stream, data);
            break;
          case sizeof(std::uint32_t):
            WriteLE<std::uint32_t>(stream, data);
            break;
          case sizeof(std::uint64_t):
            WriteLE<std::uint64_t>(stream, data);
            break;
          default:
            IOStream_Write(stream, data, type.m_Size);
            break;
        }
      }
      else
      {
        for (const BinarySchema::StructureMember& member : type.m_Members)
        {
          WriteQualifiedType(stream, type, data, member.GetMemberData(data), *member.base_type, member.type_ctors.begin(), member.type_ctors.end());
        }
      }

      return stream->error_state;
    }
  }  // namespace WriteInternal

  namespace ReadInternal
  {
    static binaryIO::IOErrorCode ReadUnqualifiedType(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, void* const data, const SchemaType& type);

    static binaryIO::IOErrorCode ReadQualifiedType(binaryIO::IOStream* const stream,
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
        const TypeConstructorByteCodeResult byte_code    = ByteCodeInternal::ReadTypeCtorBytecode(type_bytecode, parent_type, parent_object);
        const ArrayCountType                num_elements = byte_code.num_elements;
        const SizeType                      stride       = ByteCodeInternal::GetTypeSize(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);

        void* write_location = data;

        if (byte_code.flags & TypeConstructorFlags::HeapAllocated)
        {
          std::uint8_t                is_non_null;
          const binaryIO::IOErrorCode io_result = IOStream_Read(stream, &is_non_null, sizeof(is_non_null)).ErrorCode();

          if (io_result != binaryIO::IOErrorCode::Success)
          {
            is_non_null = false;
          }

          write_location                  = is_non_null ? MemAllocate(memory, num_elements * stride, base_type.m_Alignment) : (void*)nullptr;
          *reinterpret_cast<void**>(data) = write_location;
        }

        if (write_location)
        {
          for (ArrayCountType i = 0u; i < num_elements; ++i)
          {
            void* const element = static_cast<char*>(write_location) + stride * i;

            ReadQualifiedType(stream, memory, parent_type, parent_object, element, base_type, type_bytecode, type_bytecode_end);
          }
        }
      }
      else
      {
        ReadUnqualifiedType(stream, memory, data, base_type);
      }

      return stream->error_state;
    }

    template<typename T>
    static void ReadLE(binaryIO::IOStream* const stream, void* const data)
    {
      static_assert(std::is_integral_v<T>, "Expected to be an integer type.");

      binaryIO::readLE(stream, static_cast<T*>(data));
    }

    static binaryIO::IOErrorCode ReadUnqualifiedType(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, void* const data, const SchemaType& type)
    {
      if (type.IsScalar())
      {
        switch (type.m_Size)
        {
          case sizeof(std::uint8_t):
            ReadLE<std::uint8_t>(stream, data);
            break;
          case sizeof(std::uint16_t):
            ReadLE<std::uint16_t>(stream, data);
            break;
          case sizeof(std::uint32_t):
            ReadLE<std::uint32_t>(stream, data);
            break;
          case sizeof(std::uint64_t):
            ReadLE<std::uint64_t>(stream, data);
            break;
          default:
            IOStream_Read(stream, data, type.m_Size);
            break;
        }
      }
      else
      {
        for (const BinarySchema::StructureMember& member : type.m_Members)
        {
          ReadQualifiedType(stream, memory, type, data, member.GetMemberData(data), *member.base_type, member.type_ctors.begin(), member.type_ctors.end());
        }
      }

      return stream->error_state;
    }
  }  // namespace ReadInternal

  namespace ConvertInternal
  {
    static void ConvertUnqualifiedType(IPolymorphicAllocator& dst_memory,
                                       const void* const      src_data,
                                       void* const            dst_data,
                                       const SchemaType&      src_type,
                                       const SchemaType&      dst_type) noexcept;

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
                                     const TypeByteCode*       dst_type_bytecode) noexcept
    {
      if (type_bytecode != type_bytecode_end)
      {
        const TypeConstructorByteCodeResult src_byte_code     = ByteCodeInternal::ReadTypeCtorBytecode(type_bytecode, src_parent_type, src_parent_object);
        const TypeConstructorByteCodeResult dst_byte_code     = ByteCodeInternal::ReadTypeCtorBytecode(dst_type_bytecode, src_parent_type, src_parent_object);
        const TypeConstructorFlags          src_type_flags    = src_byte_code.flags;
        const TypeConstructorFlags          dst_type_flags    = dst_byte_code.flags;
        const ArrayCountType                num_data_elements = std::min(src_byte_code.num_elements, dst_byte_code.num_elements);
        const SizeType                      src_stride        = ByteCodeInternal::GetTypeSize(src_parent_type, src_parent_object, src_type, type_bytecode, type_bytecode_end);
        const SizeType                      dst_stride        = ByteCodeInternal::GetTypeSize(src_parent_type, src_parent_object, dst_type, type_bytecode, type_bytecode_end);

        // Patchwork if converting from a fixed size to a dynamic size.
        // Writes the number of elements to the dynamic member field.
        if (!ByteCodeIsDynamicallySized(src_type_flags) && ByteCodeIsDynamicallySized(dst_type_flags))
        {
          const std::uint32_t dynamic_size_offset = DynamicSize_GetOffset(dst_byte_code.dyn_size);
          const std::uint32_t dynamic_size_class  = DynamicSize_GetSize(dst_byte_code.dyn_size);
          void* const         num_elements_data   = reinterpret_cast<byte*>(dst_parent_object) + dynamic_size_offset;

          std::memset(num_elements_data, 0x0, dynamic_size_class);
          std::memcpy(num_elements_data, &num_data_elements, std::min(dynamic_size_class, std::uint32_t(sizeof(num_data_elements))));
        }

        const void* read_location  = src_object;
        void*       write_location = dst_object;

        if (src_type_flags & TypeConstructorFlags::HeapAllocated)
        {
          read_location = *static_cast<const void* const*>(src_object);
        }

        if (dst_type_flags & TypeConstructorFlags::HeapAllocated)
        {
          const bool        is_fixed_size   = dst_type_flags & TypeConstructorFlags::FixedSize;  // Fixed sized heap array are expected to always be a certain size.
          const MemoryIndex allocation_size = static_cast<MemoryIndex>(is_fixed_size ? dst_byte_code.num_elements : num_data_elements) * dst_stride;

          write_location = (read_location && allocation_size != 0) ? MemAllocate(dst_memory, allocation_size, dst_type.m_Alignment) : (void*)nullptr;

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

    template<typename...>
    struct TypeList
    {
    };

    using ScalarTypeList = TypeList<bool, char, std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, std::int8_t, std::int16_t, std::int32_t, std::int64_t, float, double>;

    template<typename T>
    static bool IsType(const SchemaType& type) noexcept
    {
      return type.m_Name.hash == TypeName<T>.hash_str.hash;
    }

    template<typename SrcType, typename T>
    static bool TryConvert_Dst(const void* const src_data, void* const dst_data, const SchemaType& dst_type) noexcept
    {
      const bool name_matches = IsType<T>(dst_type);

      if (name_matches)
      {
        *static_cast<T*>(dst_data) = static_cast<T>(*static_cast<const SrcType*>(src_data));
      }

      return name_matches;
    }

    template<typename SrcType, typename... Ts>
    static bool TryConvert_DstEntry(const void* const src_data, void* const dst_data, const SchemaType& dst_type, TypeList<Ts...>) noexcept
    {
      return (TryConvert_Dst<SrcType, Ts>(src_data, dst_data, dst_type) || ...);
    }

    template<typename T>
    static bool TryConvert_Src(const void* const src_data, void* const dst_data, const SchemaType& src_type, const SchemaType& dst_type) noexcept
    {
      return IsType<T>(src_type) && TryConvert_DstEntry<T>(src_data, dst_data, dst_type, ScalarTypeList{});
    }

    template<typename... Ts>
    static bool TryConvert_SrcEntry(const void* const src_data, void* const dst_data, const SchemaType& src_type, const SchemaType& dst_type, TypeList<Ts...>) noexcept
    {
      return (TryConvert_Src<Ts>(src_data, dst_data, src_type, dst_type) || ...);
    }

    static bool TryConvert(const void* const src_data, void* const dst_data, const SchemaType& src_type, const SchemaType& dst_type) noexcept
    {
      return TryConvert_SrcEntry(src_data, dst_data, src_type, dst_type, ScalarTypeList{});
    }

    static void ConvertUnqualifiedType(IPolymorphicAllocator& dst_memory,
                                       const void* const      src_data,
                                       void* const            dst_data,
                                       const SchemaType&      src_type,
                                       const SchemaType&      dst_type) noexcept
    {
      const auto ConvertMember = [&](const BinarySchema::StructureMember& dst_member, const BinarySchema::StructureMember& src_member) -> void {
        ConvertQualifiedType(src_type,
                             src_data,
                             *src_member.base_type,
                             src_member.GetMemberData(src_data),
                             dst_type,
                             dst_data,
                             *dst_member.base_type,
                             dst_member.GetMemberData(dst_data),
                             dst_memory,
                             src_member.type_ctors.begin(),
                             src_member.type_ctors.end(),
                             dst_member.type_ctors.begin());
      };

      const bool is_same_type = src_type == dst_type;

      if (is_same_type)
      {
        if (src_type.IsScalar())
        {
          std::memcpy(dst_data, src_data, src_type.m_Size);
        }
        else
        {
          for (std::size_t member_index = 0, member_count = dst_type.m_Members.num_elements; member_index < member_count; ++member_index)
          {
            ConvertMember(dst_type.m_Members[member_index], src_type.m_Members[member_index]);
          }
        }
      }
      else
      {
        if (src_type.IsScalar() && dst_type.IsScalar())
        {
          if (!TryConvert(src_data, dst_data, src_type, dst_type))
          {
            // TODO(SR): Error??
          }
        }
        else
        {
          for (const BinarySchema::StructureMember& dst_member : dst_type.m_Members)
          {
            const StructureMember* const src_member = src_type.FindMember(dst_member.name.hash);

            if (src_member && src_member->IsConvertCompatibleWith(dst_member))
            {
              ConvertMember(dst_member, *src_member);
            }
          }
        }
      }
    }
  }  // namespace ConvertInternal

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
        const TypeConstructorByteCodeResult byte_code         = ByteCodeInternal::ReadTypeCtorBytecode(type_bytecode, parent_type, parent_object);
        const bool                          is_heap_allocated = byte_code.flags & TypeConstructorFlags::HeapAllocated;
        void* const                         data_location     = is_heap_allocated ? *static_cast<void* const*>(data) : data;

        if (data_location)
        {
          const SizeType       stride       = ByteCodeInternal::GetTypeSize(parent_type, parent_object, base_type, type_bytecode, type_bytecode_end);
          const ArrayCountType num_elements = byte_code.num_elements;

          for (ArrayCountType i = 0u; i < num_elements; ++i)
          {
            void* const element = static_cast<char*>(data_location) + stride * i;

            FreeQualifiedType(memory, parent_type, parent_object, element, base_type, type_bytecode, type_bytecode_end);
          }

          if (is_heap_allocated)
          {
            MemDeallocate(memory, data_location, num_elements * stride, base_type.m_Alignment);
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
      for (const BinarySchema::StructureMember& member : type.m_Members)
      {
        FreeQualifiedType(memory, type, data, member.GetMemberData(data), *member.base_type, member.type_ctors.begin(), member.type_ctors.end());
      }
    }
  }  // namespace FreeInternal

}  // namespace BinarySchema

#pragma region Builder API

struct BinarySchema::build_internal::MemberBuilder
{
  BuilderName   name;
  SizeType      offset;
  HashStr32     base_type_name;
  std::uint32_t qualifier_offset;
  std::uint32_t qualifier_count;
};
static_assert(std::is_trivially_destructible_v<BinarySchema::build_internal::MemberBuilder>, "Destructor is not called.");

struct BinarySchema::build_internal::TempListChunk
{
  void*          data     = nullptr;
  std::size_t    size     = 0;
  std::size_t    capacity = 0;
  TempListChunk* next     = nullptr;
};
static_assert(std::is_trivially_destructible_v<BinarySchema::build_internal::TempListChunk>, "Destructor is not called.");

struct BinarySchema::build_internal::TypeBuilder
{
  BuilderName     name;
  SchemaTypeFlags flags;
  SizeType        size;
  std::uint16_t   alignment;
  std::uint32_t   member_offset;
  std::uint32_t   member_count;
};
static_assert(std::is_trivially_destructible_v<BinarySchema::build_internal::TypeBuilder>, "Destructor is not called.");

struct BinarySchema::build_internal::TypeTableChunk
{
  static constexpr std::size_t TableCapacity = 256;
  static constexpr std::size_t MaxCount      = (TableCapacity * 3) / 4;
  static constexpr std::size_t BloomWords    = 4;

  uint64_t        bloom[BloomWords]   = {};
  TypeBuilder*    keys[TableCapacity] = {};
  std::size_t     count               = 0u;
  TypeTableChunk* next                = nullptr;
};
static_assert(std::is_trivially_destructible_v<BinarySchema::build_internal::TypeTableChunk>, "Destructor is not called.");

namespace
{
  static constexpr uint32_t HashMix(uint32_t x)
  {
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    return x;
  }

  namespace bloom_filter
  {
    static constexpr bool TestBit(const BinarySchema::build_internal::TypeTableChunk& chunk, const uint32_t h)
    {
      constexpr uint32_t Bits = BinarySchema::build_internal::TypeTableChunk::BloomWords * 64;

      const uint32_t bit = h % Bits;

      return (chunk.bloom[bit >> 6] & (1ull << (bit & 63))) != 0;
    }

    static void SetBit(BinarySchema::build_internal::TypeTableChunk* const chunk, const uint32_t h)
    {
      constexpr uint32_t Bits = BinarySchema::build_internal::TypeTableChunk::BloomWords * 64;

      const uint32_t bit = h % Bits;

      chunk->bloom[bit >> 6] |= 1ull << (bit & 63);
    }

    static bool MayContain(const BinarySchema::build_internal::TypeTableChunk& chunk, const BinarySchema::HashStr32 name)
    {
      const uint32_t hash = name.hash;
      const uint32_t h1   = hash;
      const uint32_t h2   = HashMix(hash);

      return TestBit(chunk, h1) && TestBit(chunk, h2) && TestBit(chunk, h1 + h2);
    }

    static void AddHash(BinarySchema::build_internal::TypeTableChunk* const chunk, const BinarySchema::HashStr32 name)
    {
      const uint32_t hash = name.hash;
      const uint32_t h1   = hash;
      const uint32_t h2   = HashMix(hash);

      SetBit(chunk, h1);
      SetBit(chunk, h2);
      SetBit(chunk, h1 + h2);
    }
  }

  namespace type_tbl
  {
    static std::optional<std::size_t> Find(const BinarySchema::build_internal::TypeTableChunk& chunk, const BinarySchema::HashStr32 hash)
    {
      constexpr std::size_t Mask = BinarySchema::build_internal::TypeTableChunk::TableCapacity - 1;

      std::size_t index = HashMix(hash.hash) & Mask;

      while (true)
      {
        BinarySchema::build_internal::TypeBuilder* const slot = chunk.keys[index];

        if (slot == nullptr)
        {
          return std::nullopt;
        }
        else if (slot->name.hash_str.hash == hash.hash)
        {
          return index;
        }

        index = (index + 1) & Mask;
      }
    }

    static void AppendChunk(const AllocatorView allocator, BinarySchema::build_internal::TypeBuilderTable* const table)
    {
      auto* const new_chunk = MemAllocateT<BinarySchema::build_internal::TypeTableChunk>(allocator);

      Memory::SetBytes(new_chunk, 0x0, sizeof(*new_chunk));

      new_chunk->next   = table->tail_chunk;
      table->tail_chunk = new_chunk;
    }

    static BinarySchema::build_internal::TypeBuilder** Insert(BinarySchema::build_internal::TypeTableChunk* const chunk, const BinarySchema::HashStr32 name)
    {
      constexpr std::size_t Mask = BinarySchema::build_internal::TypeTableChunk::TableCapacity - 1;

      std::size_t index = HashMix(name.hash) & Mask;

      while (true)
      {
        BinarySchema::build_internal::TypeBuilder*& slot = chunk->keys[index];

        if (slot == nullptr)
        {
          slot = nullptr;
          bloom_filter::AddHash(chunk, name);
          ++chunk->count;
          return &slot;
        }

        index = (index + 1) & Mask;
      }
    }

    static BinarySchema::build_internal::TypeBuilder** Upsert(BinarySchema::build_internal::TypeBuilderTable* const table, const AllocatorView allocator, const BinarySchema::HashStr32 name)
    {
      for (BinarySchema::build_internal::TypeTableChunk* chunk = table->tail_chunk; chunk != nullptr; chunk = chunk->next)
      {
        if (bloom_filter::MayContain(*chunk, name))
        {
          const std::optional<std::size_t> table_index = type_tbl::Find(*chunk, name);

          if (table_index)
          {
            return &chunk->keys[*table_index];
          }
        }
      }

      if (table->tail_chunk == nullptr || table->tail_chunk->count == BinarySchema::build_internal::TypeTableChunk::MaxCount)
      {
        type_tbl::AppendChunk(allocator, table);
      }

      return type_tbl::Insert(table->tail_chunk, name);
    }

    static void FreeMemory(const AllocatorView allocator, const BinarySchema::build_internal::TypeBuilderTable& table)
    {
      BinarySchema::build_internal::TypeTableChunk* chunk = table.tail_chunk;

      while (chunk != nullptr)
      {
        BinarySchema::build_internal::TypeTableChunk* const chunk_next = chunk->next;

        MemDeallocateT(allocator, chunk);

        chunk = chunk_next;
      }
    }
  }

  namespace type_lst
  {
    template<typename T>
    static T* EmplaceBack(const AllocatorView allocator, BinarySchema::build_internal::TempList<T>* const list)
    {
      // Check Current Tail and Grow
      {
        BinarySchema::build_internal::TempListChunk* const tail_chunk = list->tail_chunk;

        if (tail_chunk == nullptr || tail_chunk->size == tail_chunk->capacity)
        {
          const std::size_t new_capacity = tail_chunk != nullptr ? tail_chunk->capacity * 2 : 8;

          MemoryRequirements size_align{};
          size_align.Append<BinarySchema::build_internal::TempListChunk>();
          const MemoryIndex data_offset = size_align.Append(sizeof(T), new_capacity, alignof(T));

          byte* const allocation = static_cast<byte*>(MemAllocate(allocator, size_align.size, size_align.alignment).ptr);
          auto*       new_chunk  = reinterpret_cast<BinarySchema::build_internal::TempListChunk*>(allocation);

          new_chunk->data     = allocation + data_offset;
          new_chunk->size     = 0;
          new_chunk->capacity = new_capacity;
          new_chunk->next     = nullptr;

          if (list->head_chunk == nullptr)
          {
            list->head_chunk = new_chunk;
          }
          else
          {
            list->tail_chunk->next = new_chunk;
          }

          list->tail_chunk = new_chunk;
        }
      }
      {
        BinarySchema::build_internal::TempListChunk* const tail_chunk = list->tail_chunk;

        T* const result = static_cast<T*>(tail_chunk->data) + (tail_chunk->size++);

        ++list->size;
        return result;
      }
    }

    template<typename T, typename CallbackFn>
    static void ForEach(const BinarySchema::build_internal::TempList<T>& list, CallbackFn&& Callback)
    {
      const BinarySchema::build_internal::TempListChunk* chunk        = list.head_chunk;
      std::size_t                                        global_index = 0u;

      while (chunk != nullptr)
      {
        const std::size_t                                        chunk_size = chunk->size;
        const BinarySchema::build_internal::TempListChunk* const chunk_next = chunk->next;
        T* const                                                 chunk_data = static_cast<T*>(chunk->data);

        for (std::size_t local_index = 0u; local_index < chunk_size; ++local_index)
        {
          Callback(global_index + local_index, chunk_data[local_index]);
        }

        global_index += chunk_size;
        chunk         = chunk_next;
      }
    }

    static void FreeMemory(const AllocatorView allocator, BinarySchema::build_internal::TempListChunk* const head_chunk, const MemoryIndex element_size, const MemoryIndex element_align)
    {
      BinarySchema::build_internal::TempListChunk* chunk = head_chunk;

      while (chunk != nullptr)
      {
        BinarySchema::build_internal::TempListChunk* const chunk_next = chunk->next;

        MemoryRequirements size_align{};
        size_align.Append<BinarySchema::build_internal::TempListChunk>();
        size_align.Append(element_size, chunk->capacity, element_align);

        MemDeallocate(allocator, chunk, size_align.size, size_align.alignment);

        chunk = chunk_next;
      }
    }

    template<typename T>
    static void FreeMemory(const AllocatorView allocator, const BinarySchema::build_internal::TempList<T>& list)
    {
      FreeMemory(allocator, list.head_chunk, sizeof(T), alignof(T));
    }
  }

}

void BinarySchema::Builder::AddQualifier_Internal(build_internal::MemberBuilder& member, TypeConstructorFlags flags_part, std::uint32_t size_part)
{
  if (flags_part == TypeConstructorFlags::DynamicArray)
  {
    binaryIOAssert(member.name.hash_str.hash != size_part, "Assigning dynamic size recursively is not valid.");
  }

#if 0
  if (flags_part == TypeConstructorFlags::DynamicArray)
  {
    const build_internal::MemberBuilder* dynamic_size_member = nullptr;

    type_lst::ForEach(type->members, [&](const std::size_t /* index */, const build_internal::MemberBuilder& member) -> void {
      if (member.name.hash == size_part)
      {
        dynamic_size_member = &member;
      }
    });

    binaryIOAssert(dynamic_size_member, "Dynamic size member must be registered before the dynamic array member.");
  }
#endif

  const TypeConstructorFlags encoded_flags = ByteCodeEncodeFlags(flags_part, size_part);

  *type_lst::EmplaceBack(allocator, &qualifier_list) = static_cast<TypeByteCode>(encoded_flags);
  if (!ByteCodeHasSmallSize(encoded_flags))
  {
    TypeByteCode size_bytes[sizeof(size_part)];
    std::memcpy(size_bytes, &size_part, sizeof(size_part));

    for (const TypeByteCode size_byte : size_bytes)
    {
      *type_lst::EmplaceBack(allocator, &qualifier_list) = size_byte;
    }
  }

  member.qualifier_count = std::uint32_t(qualifier_list.size - member.qualifier_offset);
}

void BinarySchema::Builder::SetBaseType(build_internal::MemberBuilder& member, const build_internal::TypeBuilder* const type)
{
  member.base_type_name = type->name.hash_str;
}

BinarySchema::build_internal::MemberBuilder& BinarySchema::Builder::AddMember_Internal(const BuilderName name, const SizeType byte_offset)
{
  build_internal::MemberBuilder* const new_member = type_lst::EmplaceBack(allocator, &member_list);

  new_member->name             = name;
  new_member->offset           = byte_offset;
  new_member->base_type_name   = "";
  new_member->qualifier_offset = std::uint32_t(qualifier_list.size);
  new_member->qualifier_count  = 0;
  ++current_type->member_count;

  return *new_member;
}

BinarySchema::Builder::Builder(const AllocatorView allocator) :
  allocator{allocator},
  type_table{},
  type_list{},
  member_list{},
  qualifier_list{},
  current_type{nullptr}
{
}

BinarySchema::Builder::~Builder()
{
  type_lst::FreeMemory(allocator, qualifier_list);
  type_lst::FreeMemory(allocator, member_list);
  type_lst::FreeMemory(allocator, type_list);
  type_tbl::FreeMemory(allocator, type_table);
}

template<std::size_t N>
static void ZeroPaddingBetweenPtrs(void* const (&ptrs)[N])
{
  for (std::size_t ptr_index = 0; ptr_index < (N - 1); ++ptr_index)
  {
    byte* const bgn = static_cast<byte*>(ptrs[ptr_index + 0]);
    byte* const end = static_cast<byte*>(ptrs[ptr_index + 1]);

    if (bgn != nullptr && end != nullptr)
    {
      const std::ptrdiff_t bytes = end - bgn;

      Memory::SetBytes(bgn, 0x0, bytes);
    }
  }
}

BinarySchema::Schema BinarySchema::Builder::BuildSchema(IPolymorphicAllocator& allocator) const
{
  constexpr bool KeepDebugStringData = false;

  std::uint32_t string_table_length = 0u;

  if constexpr (KeepDebugStringData)
  {
    type_lst::ForEach(type_list, [&](const std::size_t type_index, const build_internal::TypeBuilder& type) -> void {
      string_table_length += (type.name.str_length + 1);
    });

    type_lst::ForEach(member_list, [&](const std::size_t member_index, const build_internal::MemberBuilder& member) -> void {
      string_table_length += (member.name.str_length + 1);
    });
  }

  MemoryRequirements data_size_align{};
  {
    data_size_align.Append<SchemaType>(type_list.size);
    data_size_align.Append<StructureMember>(member_list.size);
    data_size_align.Append<TypeByteCode>(qualifier_list.size);
    data_size_align.Append<char>(string_table_length);
  }

  const SharedPtr<byte[]> raw_bytes = bfMemMakeShared<byte[]>(&allocator, data_size_align.size, data_size_align.alignment);

  Schema schema{};
  schema.type_id             = SchemaHeader::ChunkID;
  schema.data_size           = data_size_align.size;
  schema.num_types           = std::uint32_t(type_list.size);
  schema.num_members         = std::uint32_t(member_list.size);
  schema.num_qualifiers      = std::uint32_t(type_list.size);
  schema.string_table_length = string_table_length;
  schema.types               = bfMemMakeSharedAliasArray(raw_bytes, reinterpret_cast<SchemaType*>(raw_bytes.get()));

  {
    byte* bytes_current = raw_bytes.get();

    if (bytes_current)
    {
#if BINARY_SCHEMA_BUILD_VALIDATION
      binaryIOAssert(data_size_align.IsBufferValid(bytes_current, data_size_align.size), "Data buffer is not properly aligned.");
#endif

      // Allocations

      const void* const      memory_end = bytes_current + data_size_align.size;
      SchemaType* const      types      = MemoryRequirements::Alloc<SchemaType>(&bytes_current, memory_end, schema.num_types);
      StructureMember* const members    = MemoryRequirements::Alloc<StructureMember>(&bytes_current, memory_end, schema.num_members);
      TypeByteCode* const    qualifiers = MemoryRequirements::Alloc<TypeByteCode>(&bytes_current, memory_end, schema.num_qualifiers);
      char* const            strings    = MemoryRequirements::Alloc<char>(&bytes_current, memory_end, schema.string_table_length);

      auto CopyName = [&, write_offset = std::uint32_t(0)](const BuilderName& name) mutable -> StrName {
        StrName result = {name.hash_str.hash, nullptr};

        if constexpr (KeepDebugStringData)
        {
          result.debug_name.offset = write_offset;

          std::memcpy(strings + write_offset, name.str, name.str_length);
          write_offset            += name.str_length;
          strings[write_offset++]  = '\0';
        }

        return result;
      };

      const auto FixupString = [strings](StrName* const name) {
        if constexpr (KeepDebugStringData)
        {
          name->debug_name = strings + name->debug_name.offset;
        }
      };

      // Zero out any padding between allocations.
      {
        ZeroPaddingBetweenPtrs({types, members, qualifiers, strings});
      }
      // Convert Types
      {
        type_lst::ForEach(type_list, [&](const std::size_t type_index, const build_internal::TypeBuilder& src_type) -> void {
          SchemaType* const dst_type = types + type_index;

          dst_type->m_Name                    = CopyName(src_type.name);
          dst_type->m_Flags                   = src_type.flags;
          dst_type->m_Size                    = src_type.size;
          dst_type->m_Alignment               = src_type.alignment;
          dst_type->m_Members.elements.offset = src_type.member_offset;
          dst_type->m_Members.num_elements    = src_type.member_count;
        });

        std::sort(types, types + schema.num_types, [](const SchemaType& lhs, const SchemaType& rhs) -> bool { return lhs.m_Name.hash < rhs.m_Name.hash; });
      }
      // Update the relative pointer address
      {
        for (std::size_t type_index = 0; type_index < schema.num_types; ++type_index)
        {
          SchemaType* const dst_type = types + type_index;

          FixupString(&dst_type->m_Name);
          dst_type->m_Members.elements = members + dst_type->m_Members.elements.offset;
        }
      }
      // Convert Members
      {
        type_lst::ForEach(member_list, [&](const std::size_t member_index, const build_internal::MemberBuilder& src_member) -> void {
          StructureMember* const dst_member = members + member_index;

          dst_member->name                    = CopyName(src_member.name);
          dst_member->base_type               = schema.FindType(src_member.base_type_name);
          dst_member->type_ctors.elements     = qualifiers + src_member.qualifier_offset;
          dst_member->type_ctors.num_elements = src_member.qualifier_count;
          dst_member->offset                  = src_member.offset;

          FixupString(&dst_member->name);
        });
      }
      // Convert Qualifiers
      {
        type_lst::ForEach(qualifier_list, [&](const std::size_t qualifier_index, const TypeByteCode& src_qualifier) -> void {
          qualifiers[qualifier_index] = src_qualifier;
        });
      }

#if BINARY_SCHEMA_BUILD_VALIDATION
      if (VerifySchema(schema))
#endif
      {
        return schema;
      }
    }
  }

  return Schema{};
}

BinarySchema::build_internal::TypeBuilder* BinarySchema::Builder::AddType_Internal(const BuilderName name, const SchemaTypeFlags flags, const std::size_t size, const std::size_t alignment, void (*Builder)(Builder& ctx))
{
  BinarySchema::build_internal::TypeBuilder** existing_type = type_tbl::Upsert(&type_table, allocator, name.hash_str);

  if (*existing_type == nullptr)
  {
    BinarySchema::build_internal::TypeBuilder* const new_type = type_lst::EmplaceBack(allocator, &type_list);

    new_type->name          = name;
    new_type->flags         = flags;
    new_type->size          = static_cast<SizeType>(size);
    new_type->alignment     = static_cast<std::uint16_t>(alignment);
    new_type->member_offset = std::uint32_t(member_list.size);
    new_type->member_count  = 0u;

    *existing_type = new_type;

    BinarySchema::build_internal::TypeBuilder* const prev_type = std::exchange(current_type, new_type);
    {
      Builder(*this);
    }
    current_type = prev_type;
  }

  return *existing_type;
}

#pragma endregion

#pragma region Runtime API

bool BinarySchema::SaveSchema(binaryIO::IOStream* const stream, const Schema& schema)
{
  const SchemaHeader& header = schema;

  binaryIO::IOStream_Write(stream, &header, sizeof(header));
  binaryIO::IOStream_Write(stream, schema.types.get(), schema.data_size);

  return stream->error_state == binaryIO::IOErrorCode::Success;
}

bool BinarySchema::SaveObject(binaryIO::IOStream* const stream, const SchemaType& type, const void* const data)
{
  return WriteInternal::WriteUnqualifiedType(stream, data, type) == binaryIO::IOErrorCode::Success;
}

bool BinarySchema::LoadSchema(binaryIO::IOStream* const stream, Schema* const schema, IPolymorphicAllocator& allocator)
{
  const binaryIO::IOResult header_read_error = binaryIO::IOStream_Read(stream, schema, sizeof(SchemaHeader));

  if (header_read_error.ErrorCode() == binaryIO::IOErrorCode::Success)
  {
    const std::uint64_t     data_size = schema->data_size;
    const SharedPtr<byte[]> data      = bfMemMakeShared<byte[]>(&allocator, data_size, alignof(SchemaType));

    const binaryIO::IOResult data_read_error = binaryIO::IOStream_Read(stream, data.get(), data_size);

    if (data_read_error.ErrorCode() == binaryIO::IOErrorCode::Success)
    {
      if (VerifySchema(*schema))
      {
        return true;
      }
    }
  }

  *schema = {};
  return false;
}

bool BinarySchema::LoadObject(binaryIO::IOStream* const stream, const SchemaType& type, void* const data, IPolymorphicAllocator& allocator)
{
  return ReadInternal::ReadUnqualifiedType(stream, allocator, data, type) == binaryIO::IOErrorCode::Success;
}

void BinarySchema::ConvertObject(const void* const src_struct, const SchemaType& src_type, void* const dst_struct, const SchemaType& dst_type, IPolymorphicAllocator& dst_memory)
{
  return ConvertInternal::ConvertUnqualifiedType(dst_memory, src_struct, dst_struct, src_type, dst_type);
}

bool BinarySchema::UpgradeObject(binaryIO::IOStream* const stream, const SchemaType& dst_type, void* const dst_struct, IPolymorphicAllocator& allocator, const SchemaType& src_type)
{
  if (src_type == dst_type)
  {
    return LoadObject(stream, dst_type, dst_struct, allocator);
  }
  else
  {
    void* const src_struct = MemAllocate(allocator, src_type.m_Size, src_type.m_Alignment).ptr;

    if (src_struct != nullptr)
    {
      const bool loaded_src_struct = LoadObject(stream, src_type, src_struct, allocator);

      if (loaded_src_struct)
      {
        ConvertObject(src_struct, src_type, dst_struct, dst_type, allocator);
      }

      BinarySchema::FreeDynamicMemory(allocator, src_type, src_struct);
      MemDeallocate(allocator, src_struct, src_type.m_Size, src_type.m_Alignment);

      return loaded_src_struct;
    }

    return false;
  }
}

void BinarySchema::FreeDynamicMemory(IPolymorphicAllocator& memory, const SchemaType& type, void* const data)
{
  FreeInternal::FreeUnqualifiedType(memory, data, type);
}

#pragma endregion

/******************************************************************************/
/*
  MIT License

  Copyright (c) 2022-2026 Shareef Abdoul-Raheem

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
