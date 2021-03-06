// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_DATASTOREUPLOAD_TEO_DATASTOREUPLOAD_H_
#define FLATBUFFERS_GENERATED_DATASTOREUPLOAD_TEO_DATASTOREUPLOAD_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {
namespace DataStoreUpload {

struct OwnerPubkey;
struct OwnerPubkeyBuilder;

struct DataStoreUpload;
struct DataStoreUploadBuilder;

struct OwnerPubkey FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef OwnerPubkeyBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_PK = 4
  };
  const flatbuffers::Vector<uint8_t> *pk() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_PK);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_PK) &&
           verifier.VerifyVector(pk()) &&
           verifier.EndTable();
  }
};

struct OwnerPubkeyBuilder {
  typedef OwnerPubkey Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_pk(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> pk) {
    fbb_.AddOffset(OwnerPubkey::VT_PK, pk);
  }
  explicit OwnerPubkeyBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<OwnerPubkey> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<OwnerPubkey>(end);
    return o;
  }
};

inline flatbuffers::Offset<OwnerPubkey> CreateOwnerPubkey(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> pk = 0) {
  OwnerPubkeyBuilder builder_(_fbb);
  builder_.add_pk(pk);
  return builder_.Finish();
}

inline flatbuffers::Offset<OwnerPubkey> CreateOwnerPubkeyDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *pk = nullptr) {
  auto pk__ = pk ? _fbb.CreateVector<uint8_t>(*pk) : 0;
  return teo::DataStoreUpload::CreateOwnerPubkey(
      _fbb,
      pk__);
}

struct DataStoreUpload FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef DataStoreUploadBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_UUID = 4,
    VT_OWNER_PUBKEYS = 6,
    VT_CONTENT_LEN = 8
  };
  const flatbuffers::String *uuid() const {
    return GetPointer<const flatbuffers::String *>(VT_UUID);
  }
  const flatbuffers::Vector<flatbuffers::Offset<teo::DataStoreUpload::OwnerPubkey>> *owner_pubkeys() const {
    return GetPointer<const flatbuffers::Vector<flatbuffers::Offset<teo::DataStoreUpload::OwnerPubkey>> *>(VT_OWNER_PUBKEYS);
  }
  int32_t content_len() const {
    return GetField<int32_t>(VT_CONTENT_LEN, 0);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_UUID) &&
           verifier.VerifyString(uuid()) &&
           VerifyOffset(verifier, VT_OWNER_PUBKEYS) &&
           verifier.VerifyVector(owner_pubkeys()) &&
           verifier.VerifyVectorOfTables(owner_pubkeys()) &&
           VerifyField<int32_t>(verifier, VT_CONTENT_LEN) &&
           verifier.EndTable();
  }
};

struct DataStoreUploadBuilder {
  typedef DataStoreUpload Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_uuid(flatbuffers::Offset<flatbuffers::String> uuid) {
    fbb_.AddOffset(DataStoreUpload::VT_UUID, uuid);
  }
  void add_owner_pubkeys(flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<teo::DataStoreUpload::OwnerPubkey>>> owner_pubkeys) {
    fbb_.AddOffset(DataStoreUpload::VT_OWNER_PUBKEYS, owner_pubkeys);
  }
  void add_content_len(int32_t content_len) {
    fbb_.AddElement<int32_t>(DataStoreUpload::VT_CONTENT_LEN, content_len, 0);
  }
  explicit DataStoreUploadBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<DataStoreUpload> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<DataStoreUpload>(end);
    return o;
  }
};

inline flatbuffers::Offset<DataStoreUpload> CreateDataStoreUpload(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::String> uuid = 0,
    flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<teo::DataStoreUpload::OwnerPubkey>>> owner_pubkeys = 0,
    int32_t content_len = 0) {
  DataStoreUploadBuilder builder_(_fbb);
  builder_.add_content_len(content_len);
  builder_.add_owner_pubkeys(owner_pubkeys);
  builder_.add_uuid(uuid);
  return builder_.Finish();
}

inline flatbuffers::Offset<DataStoreUpload> CreateDataStoreUploadDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const char *uuid = nullptr,
    const std::vector<flatbuffers::Offset<teo::DataStoreUpload::OwnerPubkey>> *owner_pubkeys = nullptr,
    int32_t content_len = 0) {
  auto uuid__ = uuid ? _fbb.CreateString(uuid) : 0;
  auto owner_pubkeys__ = owner_pubkeys ? _fbb.CreateVector<flatbuffers::Offset<teo::DataStoreUpload::OwnerPubkey>>(*owner_pubkeys) : 0;
  return teo::DataStoreUpload::CreateDataStoreUpload(
      _fbb,
      uuid__,
      owner_pubkeys__,
      content_len);
}

inline const teo::DataStoreUpload::DataStoreUpload *GetDataStoreUpload(const void *buf) {
  return flatbuffers::GetRoot<teo::DataStoreUpload::DataStoreUpload>(buf);
}

inline const teo::DataStoreUpload::DataStoreUpload *GetSizePrefixedDataStoreUpload(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::DataStoreUpload::DataStoreUpload>(buf);
}

inline bool VerifyDataStoreUploadBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::DataStoreUpload::DataStoreUpload>(nullptr);
}

inline bool VerifySizePrefixedDataStoreUploadBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::DataStoreUpload::DataStoreUpload>(nullptr);
}

inline void FinishDataStoreUploadBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataStoreUpload::DataStoreUpload> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedDataStoreUploadBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataStoreUpload::DataStoreUpload> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace DataStoreUpload
}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_DATASTOREUPLOAD_TEO_DATASTOREUPLOAD_H_
