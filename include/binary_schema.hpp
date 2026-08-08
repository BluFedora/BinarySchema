/******************************************************************************/
/*!
 * @file   binary_schema.hpp
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
#ifndef BINARY_SCHEMA_HPP
#define BINARY_SCHEMA_HPP

#include "binaryio/binary_chunk.hpp"  // VersionType, BaseBinaryChunkHeader
#include "binaryio/binary_types.hpp"
#include "binaryio/rel_ptr.hpp"  // rel_ptr32, rel_array32

#include "memory/basic_types.hpp"  // byte, IPolymorphicAllocator, MemoryRequirements

#include <memory>    // shared_ptr
#include <optional>  // optional

#ifndef BINARY_SCHEMA_BUILD_VALIDATION
#define BINARY_SCHEMA_BUILD_VALIDATION 1  //!< For retail builds should be set to `0`, provides extra validation when building the schema.
#endif

#ifndef BINARY_SCHEMA_RUNTIME_VALIDATION
#define BINARY_SCHEMA_RUNTIME_VALIDATION 1  //!< For retail builds should be set to `0`, provides extra validation when using the schema.
#endif

namespace BinarySchema
{
  //
  // Schema API
  //

  using SizeType       = std::uint32_t;
  using ArrayCountType = std::uint32_t;

  struct HashStr32
  {
    // Fowler-Noll-Vo Hash
    static constexpr std::uint32_t FNV1a32(const char* str) noexcept
    {
      std::uint32_t hash = 0x811c9dc5;

      while (*str)
      {
        hash ^= (unsigned char)*str++;
        hash *= 0x01000193;
      }
      return hash;
    }

    std::uint32_t hash;

    constexpr HashStr32(const char* str) noexcept :
      hash(FNV1a32(str))
    {
    }

    HashStr32() noexcept = default;

    inline bool operator==(const HashStr32& rhs) const noexcept { return hash == rhs.hash; }
    inline bool operator!=(const HashStr32& rhs) const noexcept { return hash != rhs.hash; }
  };
  static_assert(sizeof(HashStr32) == sizeof(std::uint32_t), "Expected to only be the size of a u32.");

  template<typename T>
  struct HashStr32Table
  {
    binaryIO::rel_ptr32<HashStr32> keys;
    binaryIO::rel_ptr32<T>         values;
    std::uint32_t                  size;

    template<typename F>
    void ForEach(F&& callback) const
    {
      for (std::uint32_t i = 0u; i < size; ++i)
      {
        callback(keys[i], values[i]);
      }
    }

    T* Find(const HashStr32 name) const noexcept
    {
      for (std::uint32_t i = 0u; i < size; ++i)
      {
        if (keys[i] == name)
        {
          return &values[i];
        }
      }

      return nullptr;
    }
  };

  /*!
   * @brief
   *   TypeByteCode Format:
   *     flags = Read<TypeConstructorFlags>();
   *
   *     if ByteCodeHasSmallSize(flags)
   *       num_elements = (flags & SmallSizeMask) >> SmallSizeShift.
   *     else if flags & FixedSize
   *       num_elements = Read<ArrayCountType>();
   *     else
   *       member_name  = Read<HashStr32>();
   *       num_elements = GetDynamicArrayCount(member_name);
   */
  using TypeByteCode = std::uint8_t;

  enum class TypeConstructorFlags : TypeByteCode
  {
    HeapAllocated = (1 << 0),
    FixedSize     = (1 << 1),

    FlagsMask = HeapAllocated | FixedSize,

    SmallFixedSizeMask  = 0xFF ^ FlagsMask,
    SmallFixedSizeShift = 2,
    SmallFixedSizeMax   = (1 << (8 - SmallFixedSizeShift)) - 1,

    FixedHeap    = HeapAllocated | FixedSize,
    Pointer      = FixedHeap | (1 << SmallFixedSizeShift),
    InlineArray  = FixedSize,
    DynamicArray = HeapAllocated,
  };

  struct StructureMember
  {
    binaryIO::rel_ptr32<const struct SchemaType> base_type;
    binaryIO::rel_array32<TypeByteCode>          type_ctors;
    SizeType                                     offset;

    inline bool        HasQualifiers() const noexcept { return !type_ctors.isEmpty(); }
    inline void*       GetMemberData(void* const struct_ptr) const noexcept { return reinterpret_cast<byte*>(struct_ptr) + offset; }
    inline const void* GetMemberData(const void* const struct_ptr) const noexcept { return reinterpret_cast<const byte*>(struct_ptr) + offset; }
    bool               IsConvertCompatibleWith(const StructureMember& rhs) const noexcept;
  };
  static_assert(sizeof(StructureMember) == 16u, "");

  enum class SchemaTypeFlags : std::uint16_t
  {
    None            = 0x0,
    IsTrivial       = (1 << 0),  //!< The type will be bulk copied, rather than (de)serialized member by member.
    IsScalar        = (1 << 1),  //!< The type is numeric.
    IsFloatingPoint = (1 << 2),  //!< The type is a floating point.

    IsEndianDependent  = IsTrivial | IsScalar,  //!< Will be (de)serialized in a way that byte order is taken into account (see `ByteOrder`).
    IntegerFlags       = IsTrivial | IsScalar,
    FloatingPointFlags = IsTrivial | IsScalar | IsFloatingPoint,
  };
  inline std::uint32_t operator&(const SchemaTypeFlags lhs, const SchemaTypeFlags rhs)
  {
    return std::uint32_t(lhs) & std::uint32_t(rhs);
  }

  struct SchemaType
  {
    HashStr32                       m_Name;
    SchemaTypeFlags                 m_Flags;
    std::uint16_t                   m_Alignment;
    SizeType                        m_Size;
    HashStr32Table<StructureMember> m_Members;

    bool             IsTrivial() const { return m_Flags & SchemaTypeFlags::IsTrivial; }
    bool             IsScalar() const { return m_Flags & SchemaTypeFlags::IsScalar; }
    bool             IsIntScalar() const { return m_Flags & SchemaTypeFlags::IntegerFlags; }
    bool             IsFloatScalar() const { return m_Flags & SchemaTypeFlags::FloatingPointFlags; }
    bool             IsEndianDependent() const { return (m_Flags & SchemaTypeFlags::IsEndianDependent) && m_Size > 1 && m_Size <= sizeof(std::uint64_t); }
    StructureMember* FindMember(const HashStr32 name) const;
  };
  static_assert(sizeof(SchemaType) == 24u, "When this changes must bump `SchemaHeaderVersion` and modify the `Schema::Load` function.");

  bool        operator==(const SchemaType& lhs, const SchemaType& rhs);
  inline bool operator!=(const SchemaType& lhs, const SchemaType& rhs)
  {
    return !(lhs == rhs);
  }

  enum SchemaHeaderVersion : binaryIO::VersionType
  {
    SCHEMA_VERSION_INITIAL = 0,  //!< Initial version of the binary schema format.

    SCHEMA_VERSION_ONE_PAST_LAST,                               //!< Only used to be able to automatically calculate `SCHEMA_VERSION_CURRENT`.
    SCHEMA_VERSION_CURRENT = SCHEMA_VERSION_ONE_PAST_LAST - 1,  //!< Current version of the format.
  };

  struct SchemaHeader : public binaryIO::BaseBinaryChunkHeader<SchemaHeader, SCHEMA_VERSION_CURRENT, binaryIO::MakeChunkTypeID("SBIN")>
  {
    std::uint32_t num_types = 0u;

    SchemaHeader() = default;
  };
  static_assert(sizeof(SchemaHeader) == 24u, "When this changes must bump `SchemaHeaderVersion` and modify the `Schema::Load` function.");

  struct Schema
  {
    SchemaHeader                  header;
    std::shared_ptr<const byte[]> data_bytes;

    const SchemaType* Types() const;
    const SchemaType* FindType(const HashStr32 name) const;

    binaryIO::IOErrorCode Write(binaryIO::IOStream* const stream) const;

    static std::optional<Schema> Load(binaryIO::IOStream* const stream, IPolymorphicAllocator& allocator);

    // Buffer lifetime externally managed.
    static std::optional<Schema> FromBuffer(const void* const buffer, const std::size_t buffer_size);
  };

  //
  // Builder API
  //

  template<typename T>
  struct SchemaBuilderList
  {
    T*            head         = nullptr;
    T*            tail         = nullptr;
    std::uint32_t num_elements = 0u;

    T*   Append(const AllocatorView memory);
    void Free(const AllocatorView memory);
  };

  struct SchemaBuilderMemberQualifier
  {
    TypeConstructorFlags flags;

    union
    {
      ArrayCountType fixed;
      HashStr32      dynamic;

    } num_elements;

    SchemaBuilderMemberQualifier* next;
  };

  struct SchemaBuilderMemberNode
  {
    HashStr32                                       name;
    HashStr32                                       base_type;
    SchemaBuilderList<SchemaBuilderMemberQualifier> qualifiers;
    SizeType                                        offset;
    SchemaBuilderMemberNode*                        next;
  };

  struct SchemaBuilderTypeNode
  {
    SchemaTypeFlags                            flags;
    HashStr32                                  name;
    SizeType                                   size;
    std::uint32_t                              alignment;
    SchemaBuilderList<SchemaBuilderMemberNode> members;
    SchemaBuilderTypeNode*                     next;
  };

  class MemberBuilder
  {
   private:
    AllocatorView            m_Allocator;
    SchemaBuilderTypeNode&   m_Type;
    SchemaBuilderMemberNode& m_Member;

   public:
    MemberBuilder(const AllocatorView allocator, SchemaBuilderTypeNode& type, SchemaBuilderMemberNode& member) :
      m_Allocator{allocator},
      m_Type{type},
      m_Member{member}
    {
    }

    MemberBuilder(const MemberBuilder& rhs) = delete;

    inline const MemberBuilder& Pointer() const
    {
      return AddQualifier(TypeConstructorFlags::Pointer, 1u);
    }

    inline const MemberBuilder& Array(const ArrayCountType fixed_size) const
    {
      return AddQualifier(TypeConstructorFlags::InlineArray, fixed_size);
    }

    // Dynamic member must come before this array type.
    inline const MemberBuilder& Array(const HashStr32 dynamic_size) const
    {
#if BINARY_SCHEMA_BUILD_VALIDATION
      binaryIOAssert(m_Member.name != dynamic_size, "Assigning dynamic size recursively is not valid.");

      SchemaBuilderMemberNode* dynamic_size_member = nullptr;
      for (auto member = m_Type.members.head; member; member = member->next)
      {
        if (member->name == dynamic_size)
        {
          dynamic_size_member = member;
          break;
        }
      }

      binaryIOAssert(dynamic_size_member, "Dynamic size member must be registered before the dynamic array member.");
#endif

      return AddQualifier(TypeConstructorFlags::DynamicArray, dynamic_size.hash);
    }

    inline const MemberBuilder& FixedHeap(const ArrayCountType fixed_size) const
    {
      return AddQualifier(TypeConstructorFlags::FixedHeap, fixed_size);
    }

   private:
    const MemberBuilder& AddQualifier(TypeConstructorFlags flags_part, std::uint32_t size_part) const;
  };

  class TypeBuilder
  {
   private:
    AllocatorView          m_Allocator;
    SchemaBuilderTypeNode& m_Type;

   public:
    TypeBuilder(const AllocatorView allocator, SchemaBuilderTypeNode& type) :
      m_Allocator{allocator},
      m_Type{type}
    {
    }

    TypeBuilder(const TypeBuilder& rhs) = delete;

    MemberBuilder AddMember(const HashStr32 name, const HashStr32 type_name, const std::size_t offset);
  };

  struct SchemaBuilderEndToken
  {
    friend class SchemaBuilder;

    MemoryRequirements memory_requirements;

   private:
    SchemaBuilderEndToken(const MemoryRequirements num_bytes_needed) :
      memory_requirements{num_bytes_needed}
    {
    }
  };

  class SchemaBuilder
  {
   private:
    std::uint32_t          m_NumTypes     = 0u;
    IPolymorphicAllocator* m_Memory       = nullptr;
    SchemaBuilderTypeNode* m_TypeListHead = nullptr;

   public:
    SchemaBuilder() = default;

    SchemaBuilder(const SchemaBuilder& rhs)            = delete;
    SchemaBuilder(SchemaBuilder&& rhs)                 = delete;
    SchemaBuilder& operator=(const SchemaBuilder& rhs) = delete;
    SchemaBuilder& operator=(SchemaBuilder&& rhs)      = delete;

    template<typename T>
    TypeBuilder AddType(HashStr32 name, SchemaTypeFlags flags = SchemaTypeFlags::None)
    {
      return AddType(name, sizeof(T), alignof(T), flags);
    }

    void                  Begin(IPolymorphicAllocator& working_memory);
    TypeBuilder           AddType(HashStr32 name, std::uint32_t size, std::uint32_t alignment, SchemaTypeFlags flags = SchemaTypeFlags::None);
    SchemaBuilderEndToken End();

    /*!
     * @brief
     *   Must be called after `SchemaBuilder::End` with the returned end token.
     *
     * @param memory
     *   must be atleast `SchemaBuilderEndToken::memory_requirements.size` bytes in size and
     *   aligned to `SchemaBuilderEndToken::memory_requirements.alignment`.
     *
     * @param end_token
     *   The value returned by `SchemaBuilder::End` with info on how to construct the Schema.
     *
     * @return
     *   The built schema, `memory` is non owned so must be free manually.
     */
    std::optional<Schema> Build(void* const memory, const SchemaBuilderEndToken& end_token) const;
    std::optional<Schema> Build(IPolymorphicAllocator& allocator, const SchemaBuilderEndToken& end_token) const;

    void ReleaseResources();

    ~SchemaBuilder() { ReleaseResources(); }

   private:
    std::optional<Schema> BuildInternal(std::shared_ptr<byte[]>&& data_buffer, const SchemaBuilderEndToken& end_token) const;
  };

  void AddBasicScalarTypes(SchemaBuilder* const builder);

  //
  // Serialize API
  //

  /*!
   * @brief
   *   Byte order used when reading or writing a scalar value.
   *
   *   To add a new byte order you must update any code marked "@ByteOrder" in binary_schema.cpp.
   */
  enum class ByteOrder : std::uint8_t
  {
    Native,        //!< Endianness will not be taken into account, read / written in the current machine's byte order, fastest read/write for trivial types.
    LittleEndian,  //!< Scalar types up to 64bits will be read / written as little endian.
    BigEndian,     //!< Scalar types up to 64bits will be read / written as big endian.
  };

  // Goes from in memory to byte stream.

  binaryIO::IOErrorCode Write(binaryIO::IOStream* const stream, const SchemaType& type, const void* const data, const ByteOrder byte_order = ByteOrder::Native);
  binaryIO::IOErrorCode Write(binaryIO::IOStream* const stream, const Schema& schema, const HashStr32 type_name, const void* const data, const ByteOrder byte_order = ByteOrder::Native);

  // Goes from byte stream to in memory representation.

  binaryIO::IOErrorCode Read(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, const SchemaType& type, void* const data, const ByteOrder byte_order = ByteOrder::Native);
  binaryIO::IOErrorCode Read(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, const Schema& schema, const HashStr32 type_name, void* const data, const ByteOrder byte_order = ByteOrder::Native);

  // Convert from in memory to in memory across schemas.
  // `src_struct` and `dst_struct` expected to have the same endianness.

  void Convert(const void* const src_struct, const SchemaType& src_type, void* const dst_struct, const SchemaType& dst_type, IPolymorphicAllocator& dst_memory);
  void Convert(const void* const src_struct, const Schema& src_schema, void* const dst_struct, const Schema& dst_schema, IPolymorphicAllocator& dst_memory, HashStr32 type_name);

  // Combined Read + Convert optimized for the case when the src_schema and dst_struct types are the same.

  binaryIO::IOErrorCode Upgrade(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, const SchemaType& src_type, const SchemaType& dst_type, void* const dst_struct, const ByteOrder byte_order = ByteOrder::Native);
  binaryIO::IOErrorCode Upgrade(binaryIO::IOStream* const stream, IPolymorphicAllocator& memory, const Schema& src_schema, const Schema& dst_schema, void* const dst_struct, const HashStr32 type_name, const ByteOrder byte_order = ByteOrder::Native);

  // Frees any memory dynamically allocated from either a Read, Convert or Upgrade.

  void FreeDynamicMemory(IPolymorphicAllocator& memory, const SchemaType& type, void* const data);
  void FreeDynamicMemory(IPolymorphicAllocator& memory, const Schema& schema, const HashStr32 type_name, void* const data);

}  // namespace BinarySchema

#define BinarySchema_RegisterTypeEx(T, custom_name, flags, ...)                          \
  [](BinarySchema::SchemaBuilder* const builder) -> void {                               \
    using type = T;                                                                      \
                                                                                         \
    BinarySchema::TypeBuilder type_builder = builder->AddType<type>(custom_name, flags); \
    __VA_ARGS__;                                                                         \
  }

#define BinarySchema_RegisterTypeWithFlags(T, flags, ...) \
  BinarySchema_RegisterTypeEx(T, #T, flags, __VA_ARGS__)

#define BinarySchema_RegisterType(T, ...) \
  BinarySchema_RegisterTypeEx(T, #T, ::BinarySchema::SchemaTypeFlags::None, __VA_ARGS__)

#define BinarySchema_RegisterTrivialType(T, ...) \
  BinarySchema_RegisterTypeEx(T, #T, ::BinarySchema::SchemaTypeFlags::IsTrivial, __VA_ARGS__)

#define BinarySchema_MemberEx(type_field_name, member_name, member_type) \
  type_builder.AddMember(member_name, member_type, offsetof(type, type_field_name))

#define BinarySchema_Member(member_name, member_type) \
  BinarySchema_MemberEx(member_name, #member_name, member_type)

#include <type_traits>

namespace bin_schema
{
  using BinarySchema::ArrayCountType;
  using BinarySchema::HashStr32;
  using BinarySchema::SizeType;
  using BinarySchema::TypeConstructorFlags;

#pragma region Builders

  namespace build_internal
  {
    struct TempListChunk
    {
      void*          data     = nullptr;
      std::uint32_t  size     = 0;
      std::uint32_t  capacity = 0;
      TempListChunk* next     = nullptr;
    };

    template<typename T>
    struct TempList
    {
      TempListChunk* head_chunk = nullptr;
      TempListChunk* tail_chunk = nullptr;
      std::size_t    size       = 0u;

      TempList(const TempList& rhs)            = default;
      TempList(TempList&& rhs)                 = default;
      TempList& operator=(const TempList& rhs) = default;
      TempList& operator=(TempList&& rhs)      = default;
      ~TempList()                              = default;
    };

    struct MemberQualifier
    {
      TypeConstructorFlags flags;
      union
      {
        ArrayCountType fixed;
        std::uint32_t  dynamic;

      } num_elements;
    };

    template<typename T, typename CallbackFn>
    void ForEach(const TempList<T>& list, CallbackFn&& Callback)
    {
      const TempListChunk* chunk        = list.head_chunk;
      std::size_t          global_index = 0u;

      while (chunk != nullptr)
      {
        const std::size_t          chunk_size = chunk->size;
        const TempListChunk* const chunk_next = chunk->next;
        T* const                   chunk_data = static_cast<T*>(chunk->data);

        for (std::size_t local_index = 0u; local_index < chunk_size; ++local_index)
        {
          Callback(global_index + local_index, chunk_data[local_index]);
        }

        global_index += chunk_size;
        chunk         = chunk_next;
      }
    }
  }

  struct TypeBuilder
  {
    void MarkAsTrivial();

    template<typename ClassType, typename MemberType>
    void AddMember(const BinarySchema::HashStr32 member_name, MemberType ClassType::* member_ptr);
  };

#pragma endregion

  template<typename T>
  struct Info;

  template<typename T>
  void RegisterSchema(BinarySchema::TypeBuilder& type_builder);

  // clang-format off
  template<> struct Info<bool>          { static constexpr const BinarySchema::HashStr32 TypeName = "bool"; };
  template<> struct Info<char>          { static constexpr const BinarySchema::HashStr32 TypeName = "char"; };
  template<> struct Info<std::uint8_t>  { static constexpr const BinarySchema::HashStr32 TypeName = "u8";   };
  template<> struct Info<std::uint16_t> { static constexpr const BinarySchema::HashStr32 TypeName = "u16";  };
  template<> struct Info<std::uint32_t> { static constexpr const BinarySchema::HashStr32 TypeName = "u32";  };
  template<> struct Info<std::uint64_t> { static constexpr const BinarySchema::HashStr32 TypeName = "u64";  };
  template<> struct Info<std::int8_t>   { static constexpr const BinarySchema::HashStr32 TypeName = "i8";   };
  template<> struct Info<std::int16_t>  { static constexpr const BinarySchema::HashStr32 TypeName = "i16";  };
  template<> struct Info<std::int32_t>  { static constexpr const BinarySchema::HashStr32 TypeName = "i32";  };
  template<> struct Info<std::int64_t>  { static constexpr const BinarySchema::HashStr32 TypeName = "i64";  };
  template<> struct Info<float>         { static constexpr const BinarySchema::HashStr32 TypeName = "flt";  };
  template<> struct Info<double>        { static constexpr const BinarySchema::HashStr32 TypeName = "dbl";  };
  // template<> struct Info<long double>   { static constexpr const BinarySchema::HashStr32 TypeName = "f64x"; };
  // clang-format on

  template<auto CountMember, typename T>
  struct DynArray
  {
    T* data = nullptr;
  };

  template<typename T, std::size_t N>
  struct FixedArray
  {
    T* data = nullptr;
  };

  namespace emit_internal
  {
    template<typename T, bool IsEnum = std::is_enum_v<T>>
    struct EnumType;

    template<typename T>
    struct EnumType<T, false>
    {
      using type = T;
    };

    template<typename T>
    struct EnumType<T, true>
    {
      using type = std::underlying_type_t<T>;
    };

    template<typename T>
    using EnumTypeT = typename EnumType<T>::type;

    template<typename T>
    using StripType = std::remove_cv_t<std::remove_reference_t<EnumTypeT<T>>>;

    template<typename T, typename M>
    constexpr std::size_t offset_of(M T::* member)
    {
      return reinterpret_cast<std::size_t>(&(reinterpret_cast<T const volatile*>(0)->*member));
    }
  }

  template<typename T>
  struct Emit_MemberBuilder
  {
    static void Emit(BinarySchema::MemberBuilder& member_builder)
    {
    }
  };

  template<typename T>
  struct Emit_MemberBuilder<T*>
  {
    static void Emit(BinarySchema::MemberBuilder& member_builder)
    {
      member_builder.Pointer();
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(member_builder);
    }
  };

  template<typename T, std::size_t N>
  struct Emit_MemberBuilder<T[N]>
  {
    static void Emit(BinarySchema::MemberBuilder& member_builder)
    {
      member_builder.Array(N);
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(member_builder);
    }
  };

  template<typename T, std::size_t N>
  struct Emit_MemberBuilder<FixedArray<T, N>>
  {
    static void Emit(BinarySchema::MemberBuilder& member_builder)
    {
      member_builder.FixedHeap(N);
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(member_builder);
    }
  };

  template<auto CountMember, typename T>
  struct Emit_MemberBuilder<DynArray<CountMember, T>>
  {
    static void Emit(BinarySchema::MemberBuilder& member_builder)
    {
      member_builder.Array(emit_internal::offset_of(CountMember));
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(member_builder);
    }
  };

  template<typename ClassType, typename MemberType>
  static void AddMember(BinarySchema::TypeBuilder& type_builder, const BinarySchema::HashStr32 member_name, MemberType ClassType::* member_ptr)
  {
    using RawMemberType = emit_internal::StripType<MemberType>;

    BinarySchema::MemberBuilder member_builder = type_builder.AddMember(member_name, Info<RawMemberType>::TypeName, emit_internal::offset_of(member_ptr));

    Emit_MemberBuilder<RawMemberType>::Emit(member_builder);
  }

  template<typename ClassType, typename MemberType>
  void TypeBuilder::AddMember(const BinarySchema::HashStr32 member_name, MemberType ClassType::* member_ptr)
  {
    using RawMemberType = emit_internal::StripType<MemberType>;

    // BinarySchema::MemberBuilder member_builder = type_builder.AddMember(member_name, Info<RawMemberType>::TypeName, emit_internal::offset_of(member_ptr));

    // Emit_MemberBuilder<RawMemberType>::Emit(member_builder);
  }
}

#endif /* BINARY_SCHEMA_HPP */

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
