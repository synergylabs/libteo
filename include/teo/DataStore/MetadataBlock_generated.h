// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_METADATABLOCK_TEO_METADATABLOCK_H_
#define FLATBUFFERS_GENERATED_METADATABLOCK_TEO_METADATABLOCK_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {
namespace MetadataBlock {

struct OwnerInfo;
struct OwnerInfoBuilder;

struct MetadataBlock;
struct MetadataBlockBuilder;

struct OwnerInfo FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef OwnerInfoBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_SIEVE_NONCE = 4,
    VT_OWNER_PUBKEY = 6,
    VT_SIEVE_DATA_UUID = 8,
    VT_SIEVE_DATA_HINT = 10
  };
  const flatbuffers::Vector<uint8_t> *sieve_nonce() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_SIEVE_NONCE);
  }
  const flatbuffers::Vector<uint8_t> *owner_pubkey() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_OWNER_PUBKEY);
  }
  const flatbuffers::String *sieve_data_uuid() const {
    return GetPointer<const flatbuffers::String *>(VT_SIEVE_DATA_UUID);
  }
  const flatbuffers::Vector<int32_t> *sieve_data_hint() const {
    return GetPointer<const flatbuffers::Vector<int32_t> *>(VT_SIEVE_DATA_HINT);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_SIEVE_NONCE) &&
           verifier.VerifyVector(sieve_nonce()) &&
           VerifyOffset(verifier, VT_OWNER_PUBKEY) &&
           verifier.VerifyVector(owner_pubkey()) &&
           VerifyOffset(verifier, VT_SIEVE_DATA_UUID) &&
           verifier.VerifyString(sieve_data_uuid()) &&
           VerifyOffset(verifier, VT_SIEVE_DATA_HINT) &&
           verifier.VerifyVector(sieve_data_hint()) &&
           verifier.EndTable();
  }
};

struct OwnerInfoBuilder {
  typedef OwnerInfo Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_sieve_nonce(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> sieve_nonce) {
    fbb_.AddOffset(OwnerInfo::VT_SIEVE_NONCE, sieve_nonce);
  }
  void add_owner_pubkey(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> owner_pubkey) {
    fbb_.AddOffset(OwnerInfo::VT_OWNER_PUBKEY, owner_pubkey);
  }
  void add_sieve_data_uuid(flatbuffers::Offset<flatbuffers::String> sieve_data_uuid) {
    fbb_.AddOffset(OwnerInfo::VT_SIEVE_DATA_UUID, sieve_data_uuid);
  }
  void add_sieve_data_hint(flatbuffers::Offset<flatbuffers::Vector<int32_t>> sieve_data_hint) {
    fbb_.AddOffset(OwnerInfo::VT_SIEVE_DATA_HINT, sieve_data_hint);
  }
  explicit OwnerInfoBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<OwnerInfo> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<OwnerInfo>(end);
    return o;
  }
};

inline flatbuffers::Offset<OwnerInfo> CreateOwnerInfo(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> sieve_nonce = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> owner_pubkey = 0,
    flatbuffers::Offset<flatbuffers::String> sieve_data_uuid = 0,
    flatbuffers::Offset<flatbuffers::Vector<int32_t>> sieve_data_hint = 0) {
  OwnerInfoBuilder builder_(_fbb);
  builder_.add_sieve_data_hint(sieve_data_hint);
  builder_.add_sieve_data_uuid(sieve_data_uuid);
  builder_.add_owner_pubkey(owner_pubkey);
  builder_.add_sieve_nonce(sieve_nonce);
  return builder_.Finish();
}

inline flatbuffers::Offset<OwnerInfo> CreateOwnerInfoDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *sieve_nonce = nullptr,
    const std::vector<uint8_t> *owner_pubkey = nullptr,
    const char *sieve_data_uuid = nullptr,
    const std::vector<int32_t> *sieve_data_hint = nullptr) {
  auto sieve_nonce__ = sieve_nonce ? _fbb.CreateVector<uint8_t>(*sieve_nonce) : 0;
  auto owner_pubkey__ = owner_pubkey ? _fbb.CreateVector<uint8_t>(*owner_pubkey) : 0;
  auto sieve_data_uuid__ = sieve_data_uuid ? _fbb.CreateString(sieve_data_uuid) : 0;
  auto sieve_data_hint__ = sieve_data_hint ? _fbb.CreateVector<int32_t>(*sieve_data_hint) : 0;
  return teo::MetadataBlock::CreateOwnerInfo(
      _fbb,
      sieve_nonce__,
      owner_pubkey__,
      sieve_data_uuid__,
      sieve_data_hint__);
}

struct MetadataBlock FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef MetadataBlockBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_OWNERS = 4,
    VT_DATA_UUID = 6,
    VT_DATA_HEADER = 8
  };
  const flatbuffers::Vector<flatbuffers::Offset<teo::MetadataBlock::OwnerInfo>> *owners() const {
    return GetPointer<const flatbuffers::Vector<flatbuffers::Offset<teo::MetadataBlock::OwnerInfo>> *>(VT_OWNERS);
  }
  const flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> *data_uuid() const {
    return GetPointer<const flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> *>(VT_DATA_UUID);
  }
  const flatbuffers::Vector<uint8_t> *data_header() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_DATA_HEADER);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_OWNERS) &&
           verifier.VerifyVector(owners()) &&
           verifier.VerifyVectorOfTables(owners()) &&
           VerifyOffset(verifier, VT_DATA_UUID) &&
           verifier.VerifyVector(data_uuid()) &&
           verifier.VerifyVectorOfStrings(data_uuid()) &&
           VerifyOffset(verifier, VT_DATA_HEADER) &&
           verifier.VerifyVector(data_header()) &&
           verifier.EndTable();
  }
};

struct MetadataBlockBuilder {
  typedef MetadataBlock Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_owners(flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<teo::MetadataBlock::OwnerInfo>>> owners) {
    fbb_.AddOffset(MetadataBlock::VT_OWNERS, owners);
  }
  void add_data_uuid(flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>> data_uuid) {
    fbb_.AddOffset(MetadataBlock::VT_DATA_UUID, data_uuid);
  }
  void add_data_header(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> data_header) {
    fbb_.AddOffset(MetadataBlock::VT_DATA_HEADER, data_header);
  }
  explicit MetadataBlockBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<MetadataBlock> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<MetadataBlock>(end);
    return o;
  }
};

inline flatbuffers::Offset<MetadataBlock> CreateMetadataBlock(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<teo::MetadataBlock::OwnerInfo>>> owners = 0,
    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>> data_uuid = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> data_header = 0) {
  MetadataBlockBuilder builder_(_fbb);
  builder_.add_data_header(data_header);
  builder_.add_data_uuid(data_uuid);
  builder_.add_owners(owners);
  return builder_.Finish();
}

inline flatbuffers::Offset<MetadataBlock> CreateMetadataBlockDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<flatbuffers::Offset<teo::MetadataBlock::OwnerInfo>> *owners = nullptr,
    const std::vector<flatbuffers::Offset<flatbuffers::String>> *data_uuid = nullptr,
    const std::vector<uint8_t> *data_header = nullptr) {
  auto owners__ = owners ? _fbb.CreateVector<flatbuffers::Offset<teo::MetadataBlock::OwnerInfo>>(*owners) : 0;
  auto data_uuid__ = data_uuid ? _fbb.CreateVector<flatbuffers::Offset<flatbuffers::String>>(*data_uuid) : 0;
  auto data_header__ = data_header ? _fbb.CreateVector<uint8_t>(*data_header) : 0;
  return teo::MetadataBlock::CreateMetadataBlock(
      _fbb,
      owners__,
      data_uuid__,
      data_header__);
}

inline const teo::MetadataBlock::MetadataBlock *GetMetadataBlock(const void *buf) {
  return flatbuffers::GetRoot<teo::MetadataBlock::MetadataBlock>(buf);
}

inline const teo::MetadataBlock::MetadataBlock *GetSizePrefixedMetadataBlock(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::MetadataBlock::MetadataBlock>(buf);
}

inline bool VerifyMetadataBlockBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::MetadataBlock::MetadataBlock>(nullptr);
}

inline bool VerifySizePrefixedMetadataBlockBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::MetadataBlock::MetadataBlock>(nullptr);
}

inline void FinishMetadataBlockBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::MetadataBlock::MetadataBlock> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedMetadataBlockBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::MetadataBlock::MetadataBlock> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace MetadataBlock
}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_METADATABLOCK_TEO_METADATABLOCK_H_