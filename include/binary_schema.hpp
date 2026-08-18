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

#include "memory/basic_types.hpp"    // byte, IPolymorphicAllocator, MemoryRequirements
#include "memory/smart_pointer.hpp"  // SharedPtr<T>

#include <optional>     // optional
#include <type_traits>  // underlying_type_t, remove_reference_t, remove_cv_t

#ifndef BINARY_SCHEMA_BUILD_VALIDATION
#define BINARY_SCHEMA_BUILD_VALIDATION 1  //!< For retail builds should be set to `0`, provides extra validation when building the schema.
#endif

#ifndef BINARY_SCHEMA_RUNTIME_VALIDATION
#define BINARY_SCHEMA_RUNTIME_VALIDATION 1  //!< For retail builds should be set to `0`, provides extra validation when using the schema.
#endif

namespace BinarySchema
{
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

    constexpr HashStr32(const std::uint32_t hash) noexcept :
      hash(hash)
    {
    }

    constexpr HashStr32(const char* str) noexcept :
      hash(FNV1a32(str))
    {
    }

    HashStr32() noexcept = default;
  };
  static_assert(sizeof(HashStr32) == sizeof(std::uint32_t), "Expected to only be the size of a u32.");

  struct StrName
  {
    std::uint32_t             hash;
    binaryIO::rel_ptr32<char> debug_name;
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
   *       dynamic_size = Read<DynamicSize>();
   *       num_elements = GetDynamicArrayCount(dynamic_size);
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

  enum class DynamicSize : std::uint32_t
  {
    Int8           = 0b000,
    Int16          = 0b001,
    Int32          = 0b010,
    Int64          = 0b011,
    SizeClassMask  = 0b011,
    Unsigned       = 0b000,
    Signed         = 0b100,
    SignednessMask = 0b100,
    OffsetShift    = 3,
  };

  struct StructureMember
  {
    StrName                                      name;
    binaryIO::rel_ptr32<const struct SchemaType> base_type;
    binaryIO::rel_array32<TypeByteCode>          type_ctors;
    SizeType                                     offset;

    inline bool        HasQualifiers() const noexcept { return !type_ctors.isEmpty(); }
    inline void*       GetMemberData(void* const struct_ptr) const noexcept { return reinterpret_cast<byte*>(struct_ptr) + offset; }
    inline const void* GetMemberData(const void* const struct_ptr) const noexcept { return reinterpret_cast<const byte*>(struct_ptr) + offset; }
    bool               IsConvertCompatibleWith(const StructureMember& rhs) const noexcept;
  };
  static_assert(sizeof(StructureMember) == 24u, "");

  enum class SchemaTypeFlags : std::uint16_t
  {
    None      = 0x0,
    IsTrivial = (1 << 0),  //!< The type will be bulk copied, rather than (de)serialized member by member.
    IsScalar  = (1 << 1),  //!< The type is numeric.

    IntegerFlags       = IsTrivial | IsScalar,
    FloatingPointFlags = IsTrivial | IsScalar,
  };
  inline std::uint32_t operator&(const SchemaTypeFlags lhs, const SchemaTypeFlags rhs)
  {
    return std::uint32_t(lhs) & std::uint32_t(rhs);
  }

  struct SchemaType
  {
    StrName                                m_Name;
    SchemaTypeFlags                        m_Flags;
    std::uint16_t                          m_Alignment;
    SizeType                               m_Size;
    binaryIO::rel_array32<StructureMember> m_Members;

    bool                   IsTrivial() const { return m_Flags & SchemaTypeFlags::IsTrivial; }
    const StructureMember* FindMember(const HashStr32 name) const;
  };
  static_assert(sizeof(SchemaType) == 24u, "");

  bool        operator==(const SchemaType& lhs, const SchemaType& rhs);
  inline bool operator!=(const SchemaType& lhs, const SchemaType& rhs)
  {
    return !(lhs == rhs);
  }

  struct SchemaHeader : public binaryIO::BaseBinaryChunkHeader<SchemaHeader, 0, binaryIO::MakeChunkTypeID("SBIN")>
  {
    std::uint32_t num_types           = 0u;
    std::uint32_t num_members         = 0u;
    std::uint32_t num_qualifiers      = 0u;
    std::uint32_t string_table_length = 0u;

    SchemaHeader() = default;
  };
  static_assert(sizeof(SchemaHeader) == 32u, "");

  struct Schema : public SchemaHeader
  {
    SharedPtr<SchemaType[]> types = nullptr;

    const SchemaType* FindType(const HashStr32 name) const;

    template<typename T>
    const SchemaType* FindType() const;
  };

  // Memory -> IOStream: Serialize

  bool SaveSchema(binaryIO::IOStream* const stream, const Schema& schema);
  bool SaveObject(binaryIO::IOStream* const stream, const SchemaType& type, const void* const data);

  template<typename T>
  bool SaveObject(binaryIO::IOStream* const stream, const Schema& schema, const T& data)
  {
    return SaveObject(stream, *schema.FindType<T>(), &data);
  }

  // IOStream -> Memory: Deserialize

  bool LoadSchema(binaryIO::IOStream* const stream, Schema* const schema, IPolymorphicAllocator& allocator);
  bool LoadObject(binaryIO::IOStream* const stream, const SchemaType& type, void* const data, IPolymorphicAllocator& allocator);

  // Memory -> Memory: Convert from in memory to in memory across schemas.

  void ConvertObject(const void* const src_struct, const SchemaType& src_type, void* const dst_struct, const SchemaType& dst_type, IPolymorphicAllocator& dst_memory);

  // Combined LoadObject + Convert optimized for the case when the src_type and dst_type types are the same.

  bool UpgradeObject(binaryIO::IOStream* const stream, const SchemaType& dst_type, void* const dst_struct, IPolymorphicAllocator& allocator, const SchemaType& src_type);

  // Frees any memory dynamically allocated from either a Read, Convert or Upgrade.

  void FreeDynamicMemory(IPolymorphicAllocator& memory, const SchemaType& type, void* const data);

  template<typename T>
  struct DynArray
  {
    T* ptr = nullptr;

    DynArray(T* const ptr = nullptr) :
      ptr{ptr}
    {
    }

    T& operator[](const std::size_t index) const { return ptr[index]; }
  };

  template<typename T, std::size_t N>
  struct FixedArray : public DynArray<T>
  {
  };

#pragma region Builders

  struct BuildCtx;

  struct BuilderName
  {
    constexpr std::uint32_t StringLength(const char* const str)
    {
      std::uint32_t n = 0;
      while (str[n] != '\0')
      {
        ++n;
      }
      return n;
    }

    const char*   str;
    std::uint32_t str_length;
    HashStr32     hash_str;

    constexpr BuilderName(const char* const str) :
      str{str},
      str_length{StringLength(str)},
      hash_str{str}
    {
    }
  };

  namespace build_internal
  {
    struct MemberBuilder;
    struct TempListChunk;
    struct TypeBuilder;
    struct TypeTableChunk;

    template<typename T>
    struct TempList
    {
      TempListChunk* head_chunk = nullptr;
      TempListChunk* tail_chunk = nullptr;
      std::size_t    size       = 0u;
    };

    struct TypeBuilderTable
    {
      TypeTableChunk* tail_chunk = nullptr;
    };

    using TypeBuilderList = TempList<TypeBuilder>;
    using MemberList      = TempList<MemberBuilder>;
    using QualifierList   = TempList<TypeByteCode>;
    using StringList      = TempList<const char*>;

    template<typename T>
    struct IsDynArray : std::false_type
    {
    };

    template<typename T>
    struct IsDynArray<DynArray<T>> : std::true_type
    {
    };
  }

  struct Builder
  {
    AllocatorView                    allocator;
    build_internal::TypeBuilderTable type_table;
    build_internal::TypeBuilderList  type_list;
    build_internal::MemberList       member_list;
    build_internal::QualifierList    qualifier_list;
    build_internal::TypeBuilder*     current_type;

    Builder(const AllocatorView allocator);
    ~Builder();

    template<typename T>
    build_internal::TypeBuilder* AddType();

    template<typename ClassType, typename MemberType>
    void AddMember(const BuilderName member_name, MemberType ClassType::* member_ptr);

    template<typename ClassType, typename T, typename LengthType>
    void AddMember(const BuilderName member_name, DynArray<T> ClassType::* member_ptr, LengthType ClassType::* length_ptr);

    Schema BuildSchema(IPolymorphicAllocator& allocator) const;

    Builder(const Builder& rhs)            = delete;
    Builder(Builder&& rhs)                 = delete;
    Builder& operator=(const Builder& rhs) = delete;
    Builder& operator=(Builder&& rhs)      = delete;

    static void SetBaseType(build_internal::MemberBuilder& member, const build_internal::TypeBuilder* const type);

   private:
    build_internal::TypeBuilder*   AddType_Internal(const BuilderName name, const SchemaTypeFlags flags, const std::size_t size, const std::size_t alignment, void (*Builder)(Builder& ctx));
    void                           AddQualifier_Internal(build_internal::MemberBuilder& member, TypeConstructorFlags flags_part, std::uint32_t size_part);
    build_internal::MemberBuilder& AddMember_Internal(const BuilderName name, const SizeType byte_offset);

    template<typename T>
    static DynamicSize MakeDynamicSize(const std::uint32_t offset)
    {
      constexpr DynamicSize size_class = []() -> DynamicSize {
        if constexpr (std::is_same_v<T, std::uint8_t> || std::is_same_v<T, std::int8_t>)
        {
          return DynamicSize::Int8;
        }
        else if constexpr (std::is_same_v<T, std::uint16_t> || std::is_same_v<T, std::int16_t>)
        {
          return DynamicSize::Int16;
        }
        else if constexpr (std::is_same_v<T, std::uint32_t> || std::is_same_v<T, std::int32_t>)
        {
          return DynamicSize::Int32;
        }
        else if constexpr (std::is_same_v<T, std::uint64_t> || std::is_same_v<T, std::int64_t>)
        {
          return DynamicSize::Int64;
        }
        else
        {
          static_assert(false, "Dynamic Size Length must be an an integer type.");
        }
      }();

      constexpr DynamicSize signedness = std::is_signed_v<T> ? DynamicSize::Signed : DynamicSize::Unsigned;

      return static_cast<DynamicSize>(std::uint32_t(size_class) | std::uint32_t(signedness) | offset);
    }
  };

#pragma endregion

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
    static void Emit(Builder& ctx, build_internal::MemberBuilder& member_builder)
    {
      Builder::SetBaseType(member_builder, ctx.AddType<emit_internal::StripType<T>>());
    }
  };

  template<typename T>
  struct Emit_MemberBuilder<T*>
  {
    static void Emit(Builder& ctx, build_internal::MemberBuilder& member_builder)
    {
      ctx.AddQualifier_Internal(member_builder, TypeConstructorFlags::Pointer, 1u);
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(ctx, member_builder);
    }
  };

  template<typename T, std::size_t N>
  struct Emit_MemberBuilder<T[N]>
  {
    static void Emit(Builder& ctx, build_internal::MemberBuilder& member_builder)
    {
      ctx.AddQualifier_Internal(member_builder, TypeConstructorFlags::InlineArray, N);
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(ctx, member_builder);
    }
  };

  template<typename T, std::size_t N>
  struct Emit_MemberBuilder<FixedArray<T, N>>
  {
    static void Emit(Builder& ctx, build_internal::MemberBuilder& member_builder)
    {
      ctx.AddQualifier_Internal(member_builder, TypeConstructorFlags::FixedHeap, N);
      Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(ctx, member_builder);
    }
  };

  struct TypeInfo
  {
    BuilderName     name;
    SchemaTypeFlags flags;
  };

  template<typename T>
  inline constexpr TypeInfo Type;  // = undefined;

  template<typename T>
  void DeclareMembers(Builder& ctx);  // = undefined;

  template<typename T>
  build_internal::TypeBuilder* Builder::AddType()
  {
    constexpr TypeInfo type_info = Type<T>;

    return AddType_Internal(type_info.name, type_info.flags, sizeof(T), alignof(T), &DeclareMembers<T>);
  }

  template<typename ClassType, typename MemberType>
  void Builder::AddMember(const BuilderName member_name, MemberType ClassType::* member_ptr)
  {
    static_assert(!build_internal::IsDynArray<std::remove_cv_t<MemberType>>::value, "DynArray must specify the member used for the element count.");

    build_internal::MemberBuilder& member_builder = AddMember_Internal(member_name, static_cast<SizeType>(emit_internal::offset_of(member_ptr)));

    Emit_MemberBuilder<emit_internal::StripType<MemberType>>::Emit(*this, member_builder);
  }

  // NOTE(SR): If the length field is deserialized make sure it comes before this member.
  template<typename ClassType, typename T, typename LengthType>
  void Builder::AddMember(const BuilderName member_name, DynArray<T> ClassType::* member_ptr, LengthType ClassType::* length_ptr)
  {
    build_internal::MemberBuilder& member_builder = AddMember_Internal(member_name, static_cast<SizeType>(emit_internal::offset_of(member_ptr)));

    const DynamicSize dynamic_size = MakeDynamicSize<LengthType>(static_cast<std::uint32_t>(emit_internal::offset_of(member_ptr)));

    AddQualifier_Internal(member_builder, TypeConstructorFlags::DynamicArray, static_cast<std::uint32_t>(dynamic_size));
    Emit_MemberBuilder<emit_internal::StripType<T>>::Emit(*this, member_builder);
  }

  template<typename T>
  const SchemaType* Schema::FindType() const
  {
    return FindType(BinarySchema::Type<T>.name.hash_str);
  }
}

#define BinarySchema_Type(T, flags)                                                                           \
  template<>                                                                                                  \
  inline constexpr BinarySchema::TypeInfo BinarySchema::Type<T> = {#T, BinarySchema::SchemaTypeFlags::flags}; \
                                                                                                              \
  template<>                                                                                                  \
  inline void BinarySchema::DeclareMembers<T>(BinarySchema::Builder & ctx)

BinarySchema_Type(bool, IsTrivial) {}
BinarySchema_Type(char, IntegerFlags) {}
BinarySchema_Type(std::uint8_t, IntegerFlags) {}
BinarySchema_Type(std::uint16_t, IntegerFlags) {}
BinarySchema_Type(std::uint32_t, IntegerFlags) {}
BinarySchema_Type(std::uint64_t, IntegerFlags) {}
BinarySchema_Type(std::int8_t, IntegerFlags) {}
BinarySchema_Type(std::int16_t, IntegerFlags) {}
BinarySchema_Type(std::int32_t, IntegerFlags) {}
BinarySchema_Type(std::int64_t, IntegerFlags) {}
BinarySchema_Type(float, FloatingPointFlags) {}
BinarySchema_Type(double, FloatingPointFlags) {}

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
