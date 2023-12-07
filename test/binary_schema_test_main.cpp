//
// BinarySchema Tests
//

#include "binary_schema.hpp"  // Binary Schema API

#include <catch2/catch_test_macros.hpp>  // Catch2 API

#include "assetio/binary_stream_ext.hpp"  // byteWriterViewFromVector

#include "memory/allocation.hpp"      // bfMemAllocate, bfMemDeallocate
#include "memory/default_heap.hpp"    // DefaultHeap
#include "memory/memory_manager.hpp"  // MemoryTrackAllocate, MemoryTrackDeallocate
#include "memory/stl_allocator.hpp"   // StlAllocator

#include <vector>  // vector

// Serialized Structs

struct TrivialType
{
  float x;
  float y;
  float z;
};
constexpr auto TrivialType_Register = BinarySchema_RegisterTrivialType(
 TrivialType,
 {
   BinarySchema_Member(x, "f32");
   BinarySchema_Member(y, "f32");
   BinarySchema_Member(z, "f32");
 });

struct ComplexTypeV1
{
  TrivialType* ptr;
  TrivialType  fixed_array[2];
  TrivialType* dynamic_array;
  int          dynamic_array_size;
  TrivialType* heap_array;  // Always size of 4.
};
constexpr auto ComplexTypeV1_Register = BinarySchema_RegisterTypeEx(
 ComplexTypeV1,
 "ComplexType",
 BinarySchema::SchemaTypeFlags::None,
 {
   BinarySchema_Member(ptr, "TrivialType").Pointer();
   BinarySchema_Member(fixed_array, "TrivialType").Array(sizeof(ComplexTypeV1::fixed_array) / sizeof(TrivialType));
   BinarySchema_Member(dynamic_array_size, "i32");
   BinarySchema_Member(dynamic_array, "TrivialType").Array("dynamic_array_size");
   BinarySchema_Member(heap_array, "TrivialType").FixedHeap(4);
 });

struct ComplexTypeV2
{
  TrivialType* ptr;
  TrivialType* fixed_array;  // V2: `fixed_array` is now dynamic.
  int          fixed_array_size;
  TrivialType* dynamic_array;
  int          dynamic_array_size;
  TrivialType* heap_array;  // V2: Needed to make this larger, 8 in length.
  float        new_member;  // V2: Added a new member.
};
constexpr auto ComplexTypeV2_Register = BinarySchema_RegisterTypeEx(
 ComplexTypeV2,
 "ComplexType",
 BinarySchema::SchemaTypeFlags::None,
 {
   BinarySchema_Member(ptr, "TrivialType").Pointer();
   BinarySchema_Member(fixed_array_size, "i32");
   BinarySchema_Member(fixed_array, "TrivialType").Array("fixed_array_size");
   BinarySchema_Member(dynamic_array_size, "i32");
   BinarySchema_Member(dynamic_array, "TrivialType").Array("dynamic_array_size");
   BinarySchema_Member(heap_array, "TrivialType").FixedHeap(8);
 });

// Allocator

struct ByteCounterTracking
{
  size_t num_bytes_allocated = 0u;

  void TrackAllocate(const Memory::MemoryTrackAllocate& allocate_info) noexcept
  {
    num_bytes_allocated += allocate_info.requested_bytes;
  }

  void TrackDeallocate(const Memory::MemoryTrackDeallocate& deallocate_info) noexcept
  {
    num_bytes_allocated -= deallocate_info.num_bytes;
  }
};

struct HeapAllocator
{
  AllocationResult Allocate(const MemoryIndex size, MemoryIndex alignment, const AllocationSourceInfo& source_info)
  {
    return (bfMemAllocate)(Memory::DefaultHeap(), size, alignment, source_info);
  };

  void Deallocate(void* const ptr, const MemoryIndex size, MemoryIndex alignment)
  {
    return bfMemDeallocate(Memory::DefaultHeap(), ptr, size, alignment);
  }
};

struct ByteCountingAllocator : public Allocator<Memory::MemoryManager<HeapAllocator, Memory::AllocationMarkPolicy::MARK, Memory::BoundCheckingPolicy::CHECKED, ByteCounterTracking, Memory::NoLock>>
{
};

// Test Cases

TEST_CASE("FNV1a32", "[core-functionality]")
{
  // Correct answers generated by: https://md5calc.com/hash/fnv1a32

  REQUIRE(BinarySchema::HashStr32::FNV1a32(" ") == 0x250c8f7f);
  REQUIRE(BinarySchema::HashStr32::FNV1a32("This is a test string") == 0xFFE2ACC9);
  REQUIRE(BinarySchema::HashStr32::FNV1a32("Another hash test") == 0x4BD510D0);
}

TEST_CASE("Endianness", "[core-functionality]")
{
  constexpr int32_t  le_value     = 0xF6543210;
  constexpr uint32_t be_value     = 0x76543210;
  constexpr int32_t  le_value_inv = 0x103254F6;
  constexpr uint32_t be_value_inv = 0x10325476;

  ByteCountingAllocator allocator{};
  {
    std::vector<byte, Memory::StlAllocator<byte>> bytes{allocator};
    assetio::ByteWriterView                       byte_writer = assetio::byteWriterViewFromVector(&bytes);

    REQUIRE(assetio::writeLE(byte_writer, le_value) == assetio::IOResult::Success);
    REQUIRE(assetio::writeBE(byte_writer, be_value) == assetio::IOResult::Success);
    REQUIRE(assetio::writeLE(byte_writer, le_value) == assetio::IOResult::Success);
    REQUIRE(assetio::writeBE(byte_writer, be_value) == assetio::IOResult::Success);

    assetio::IByteReader byte_reader = assetio::IByteReader::fromBuffer(bytes.data(), bytes.size());

    int32_t  le_int;
    uint32_t be_uint;
    int32_t  le_int_inv;
    uint32_t be_uint_inv;
    uint32_t invalid_uint = 0xFFFFFFFF;
    REQUIRE(assetio::readLE(byte_reader, &le_int) == assetio::IOResult::Success);
    REQUIRE(assetio::readBE(byte_reader, &be_uint) == assetio::IOResult::Success);
    REQUIRE(assetio::readBE(byte_reader, &le_int_inv) == assetio::IOResult::Success);
    REQUIRE(assetio::readLE(byte_reader, &be_uint_inv) == assetio::IOResult::Success);
    REQUIRE(assetio::readBE(byte_reader, &invalid_uint) == assetio::IOResult::EndOfStream);

    REQUIRE(le_int == le_value);
    REQUIRE(be_uint == be_value);
    REQUIRE(le_int_inv == le_value_inv);
    REQUIRE(be_uint_inv == be_value_inv);
    REQUIRE(invalid_uint == 0xFFFFFFFF);  // Expected to be untouched.
  }
  REQUIRE(allocator.num_bytes_allocated == 0);
}

TEST_CASE("Schema Builder Basics", "[BinarySchema]")
{
  SECTION("Empty Builder")
  {
    BinarySchema::SchemaBuilder builder{};
  }

  SECTION("Builder Begin / End")
  {
    ByteCountingAllocator allocator{};
    {
      BinarySchema::SchemaBuilder builder{};
      builder.Begin(allocator);
      builder.End();
    }
    REQUIRE(allocator.num_bytes_allocated == 0);
  }

  SECTION("Builder Basic Types")
  {
    ByteCountingAllocator allocator{};
    {
      BinarySchema::SchemaBuilder builder{};
      builder.Begin(allocator);
      AddBasicScalarTypes(&builder);
      builder.End();
    }
    REQUIRE(allocator.num_bytes_allocated == 0);
  }
}

TEST_CASE("Round Trip Serialization/Deserialization", "[BinarySchema]")
{
  constexpr BinarySchema::ByteOrder byte_order = BinarySchema::ByteOrder::LittleEndian;

  SECTION("Trivial Type")
  {
    ByteCountingAllocator allocator{};
    {
      BinarySchema::SchemaBuilder builder{};
      builder.Begin(allocator);
      AddBasicScalarTypes(&builder);
      TrivialType_Register(&builder);
      const BinarySchema::SchemaBuilderEndToken end_token = builder.End();
      const std::optional<BinarySchema::Schema> schema    = builder.Build(allocator, end_token);

      REQUIRE(schema.has_value());

      if (schema)
      {
        std::vector<byte, Memory::StlAllocator<byte>> serialized_object{allocator};
        assetio::ByteWriterView                       byte_writer = assetio::byteWriterViewFromVector(&serialized_object);

        const TrivialType saved_data{1.0f, 2.0f, 3.0f};

        assetio::IOResult io_result = BinarySchema::Write(byte_writer, *schema, "TrivialType", &saved_data, byte_order);

        REQUIRE(io_result == assetio::IOResult::Success);

        assetio::IByteReader byte_reader = assetio::IByteReader::fromBuffer(serialized_object.data(), serialized_object.size());
        TrivialType          loaded_data;

        io_result = BinarySchema::Read(byte_reader, allocator, *schema, "TrivialType", &loaded_data, byte_order);

        REQUIRE(io_result == assetio::IOResult::Success);

        REQUIRE(saved_data.x == loaded_data.x);
        REQUIRE(saved_data.y == loaded_data.y);
        REQUIRE(saved_data.z == loaded_data.z);
      }
    }
    REQUIRE(allocator.num_bytes_allocated == 0);
  }

  SECTION("Complex Type")
  {
    ByteCountingAllocator allocator{};
    {
      BinarySchema::SchemaBuilder builder{};
      builder.Begin(allocator);
      AddBasicScalarTypes(&builder);
      TrivialType_Register(&builder);
      ComplexTypeV1_Register(&builder);
      const BinarySchema::SchemaBuilderEndToken end_token = builder.End();
      const std::optional<BinarySchema::Schema> schema    = builder.Build(allocator, end_token);

      REQUIRE(schema.has_value());

      if (schema)
      {
        std::vector<byte, Memory::StlAllocator<byte>> serialized_object{allocator};
        assetio::ByteWriterView                       byte_writer = assetio::byteWriterViewFromVector(&serialized_object);

        const int dynamic_array_size = 3;
        const int heap_array_size    = 4;

        TrivialType   trivial_ptr{1.0f, 2.0f, 3.0f};
        ComplexTypeV1 saved_data;
        saved_data.ptr            = &trivial_ptr;
        saved_data.fixed_array[0] = {4.0f, 5.0f, 6.0f};
        saved_data.fixed_array[1] = {7.0f, 8.0f, 9.0f};
        saved_data.dynamic_array  = new TrivialType[dynamic_array_size]{
         {10.0f, 13.0f, 16.0f},
         {11.0f, 14.0f, 17.0f},
         {12.0f, 16.0f, 18.0f},
        };
        saved_data.dynamic_array_size = dynamic_array_size;
        saved_data.heap_array         = new TrivialType[heap_array_size]{
         {20.0f, 30.0f, 40.0f},
         {21.0f, 31.0f, 41.0f},
         {22.0f, 32.0f, 42.0f},
         {23.0f, 33.0f, 43.0f},
        };

        const BinarySchema::SchemaType* const complex_type = schema->FindType("ComplexType");

        REQUIRE(complex_type != nullptr);

        assetio::IOResult io_result = BinarySchema::Write(byte_writer, *complex_type, &saved_data, byte_order);

        REQUIRE(io_result == assetio::IOResult::Success);

        assetio::IByteReader byte_reader = assetio::IByteReader::fromBuffer(serialized_object.data(), serialized_object.size());
        ComplexTypeV1        loaded_data;
        std::memset(&loaded_data, 0x0, sizeof(loaded_data));

        io_result = BinarySchema::Read(byte_reader, allocator, *complex_type, &loaded_data, byte_order);

        REQUIRE(io_result == assetio::IOResult::Success);

        REQUIRE(loaded_data.ptr != nullptr);
        if (loaded_data.ptr)
        {
          REQUIRE(loaded_data.ptr->x == saved_data.ptr->x);
          REQUIRE(loaded_data.ptr->y == saved_data.ptr->y);
          REQUIRE(loaded_data.ptr->z == saved_data.ptr->z);
        }

        for (int i = 0; i < 2; ++i)
        {
          REQUIRE(loaded_data.fixed_array[i].x == saved_data.fixed_array[i].x);
          REQUIRE(loaded_data.fixed_array[i].y == saved_data.fixed_array[i].y);
          REQUIRE(loaded_data.fixed_array[i].z == saved_data.fixed_array[i].z);
        }

        REQUIRE(loaded_data.dynamic_array != nullptr);
        REQUIRE(loaded_data.dynamic_array_size == saved_data.dynamic_array_size);
        if (loaded_data.dynamic_array != nullptr)
        {
          for (int i = 0; i < dynamic_array_size; ++i)
          {
            REQUIRE(loaded_data.dynamic_array[i].x == saved_data.dynamic_array[i].x);
            REQUIRE(loaded_data.dynamic_array[i].y == saved_data.dynamic_array[i].y);
            REQUIRE(loaded_data.dynamic_array[i].z == saved_data.dynamic_array[i].z);
          }
        }

        REQUIRE(loaded_data.heap_array != nullptr);
        for (int i = 0; i < heap_array_size; ++i)
        {
          REQUIRE(loaded_data.heap_array[i].x == saved_data.heap_array[i].x);
          REQUIRE(loaded_data.heap_array[i].y == saved_data.heap_array[i].y);
          REQUIRE(loaded_data.heap_array[i].z == saved_data.heap_array[i].z);
        }

        delete[] saved_data.dynamic_array;
        delete[] saved_data.heap_array;

        BinarySchema::FreeDynamicMemory(allocator, *schema, "ComplexType", &loaded_data);
      }
    }
    REQUIRE(allocator.num_bytes_allocated == 0);
  }
}

TEST_CASE("Upgrade", "[BinarySchema]")
{
  constexpr BinarySchema::ByteOrder byte_order = BinarySchema::ByteOrder::LittleEndian;

  SECTION("Complex Type")
  {
    ByteCountingAllocator allocator{};
    {
      const std::optional<BinarySchema::Schema> schema_v1 = [&]() {
        BinarySchema::SchemaBuilder builder{};
        builder.Begin(allocator);
        AddBasicScalarTypes(&builder);
        TrivialType_Register(&builder);
        ComplexTypeV1_Register(&builder);
        const BinarySchema::SchemaBuilderEndToken end_token = builder.End();

        return builder.Build(allocator, end_token);
      }();

      const std::optional<BinarySchema::Schema> schema_v2 = [&]() {
        BinarySchema::SchemaBuilder builder{};
        builder.Begin(allocator);
        AddBasicScalarTypes(&builder);
        TrivialType_Register(&builder);
        ComplexTypeV2_Register(&builder);
        const BinarySchema::SchemaBuilderEndToken end_token = builder.End();

        return builder.Build(allocator, end_token);
      }();

      REQUIRE(schema_v1.has_value());
      REQUIRE(schema_v2.has_value());

      if (schema_v1 && schema_v2)
      {
        const BinarySchema::SchemaType* const complex_type_v1 = schema_v1->FindType("ComplexType");
        const BinarySchema::SchemaType* const complex_type_v2 = schema_v2->FindType("ComplexType");

        REQUIRE(complex_type_v1 != nullptr);
        REQUIRE(complex_type_v2 != nullptr);

        std::vector<byte, Memory::StlAllocator<byte>> serialized_object{allocator};
        assetio::ByteWriterView                       byte_writer = assetio::byteWriterViewFromVector(&serialized_object);

        const int dynamic_array_size  = 3;
        const int old_heap_array_size = 4;
        const int new_heap_array_size = 8;

        TrivialType   trivial_ptr{1.0f, 2.0f, 3.0f};
        ComplexTypeV1 saved_data;
        saved_data.ptr            = &trivial_ptr;
        saved_data.fixed_array[0] = {4.0f, 5.0f, 6.0f};
        saved_data.fixed_array[1] = {7.0f, 8.0f, 9.0f};
        saved_data.dynamic_array  = new TrivialType[dynamic_array_size]{
         {10.0f, 13.0f, 16.0f},
         {11.0f, 14.0f, 17.0f},
         {12.0f, 16.0f, 18.0f},
        };
        saved_data.dynamic_array_size = dynamic_array_size;
        saved_data.heap_array         = new TrivialType[old_heap_array_size]{
         {20.0f, 30.0f, 40.0f},
         {21.0f, 31.0f, 41.0f},
         {22.0f, 32.0f, 42.0f},
         {23.0f, 33.0f, 43.0f},
        };

        assetio::IOResult io_result = BinarySchema::Write(byte_writer, *complex_type_v1, &saved_data, byte_order);

        REQUIRE(io_result == assetio::IOResult::Success);

        assetio::IByteReader byte_reader = assetio::IByteReader::fromBuffer(serialized_object.data(), serialized_object.size());
        ComplexTypeV2        loaded_data;
        std::memset(&loaded_data, 0x0, sizeof(loaded_data));
        loaded_data.new_member = 5.5f;

        io_result = BinarySchema::Upgrade(byte_reader, allocator, *complex_type_v1, *complex_type_v2, &loaded_data, byte_order);

        REQUIRE(io_result == assetio::IOResult::Success);

        REQUIRE(loaded_data.ptr != nullptr);
        if (loaded_data.ptr)
        {
          REQUIRE(loaded_data.ptr->x == saved_data.ptr->x);
          REQUIRE(loaded_data.ptr->y == saved_data.ptr->y);
          REQUIRE(loaded_data.ptr->z == saved_data.ptr->z);
        }

        REQUIRE(loaded_data.fixed_array_size == 2);
        for (int i = 0; i < 2; ++i)
        {
          REQUIRE(loaded_data.fixed_array[i].x == saved_data.fixed_array[i].x);
          REQUIRE(loaded_data.fixed_array[i].y == saved_data.fixed_array[i].y);
          REQUIRE(loaded_data.fixed_array[i].z == saved_data.fixed_array[i].z);
        }

        REQUIRE(loaded_data.dynamic_array != nullptr);
        REQUIRE(loaded_data.dynamic_array_size == saved_data.dynamic_array_size);
        if (loaded_data.dynamic_array != nullptr)
        {
          for (int i = 0; i < dynamic_array_size; ++i)
          {
            REQUIRE(loaded_data.dynamic_array[i].x == saved_data.dynamic_array[i].x);
            REQUIRE(loaded_data.dynamic_array[i].y == saved_data.dynamic_array[i].y);
            REQUIRE(loaded_data.dynamic_array[i].z == saved_data.dynamic_array[i].z);
          }
        }

        REQUIRE(loaded_data.heap_array != nullptr);
        for (int i = 0; i < old_heap_array_size; ++i)
        {
          REQUIRE(loaded_data.heap_array[i].x == saved_data.heap_array[i].x);
          REQUIRE(loaded_data.heap_array[i].y == saved_data.heap_array[i].y);
          REQUIRE(loaded_data.heap_array[i].z == saved_data.heap_array[i].z);
        }

        constexpr uint32_t uninitialized_byte_pattern = (Memory::AllocatedBytePattern << 0u) |
                                                        (Memory::AllocatedBytePattern << 8u) |
                                                        (Memory::AllocatedBytePattern << 16u) |
                                                        (Memory::AllocatedBytePattern << 24u);

        float uninitialized_float;

        static_assert(sizeof(uninitialized_byte_pattern) == sizeof(uninitialized_float), "");

        memcpy(&uninitialized_float, &uninitialized_byte_pattern, sizeof(uninitialized_byte_pattern));

        for (int i = old_heap_array_size; i < new_heap_array_size; ++i)
        {
          REQUIRE(loaded_data.heap_array[i].x == uninitialized_float);
          REQUIRE(loaded_data.heap_array[i].y == uninitialized_float);
          REQUIRE(loaded_data.heap_array[i].z == uninitialized_float);
        }

        REQUIRE(loaded_data.new_member == 5.5f);

        delete[] saved_data.dynamic_array;
        delete[] saved_data.heap_array;

        BinarySchema::FreeDynamicMemory(allocator, *complex_type_v2, &loaded_data);
      }
    }
    REQUIRE(allocator.num_bytes_allocated == 0);
  }
}