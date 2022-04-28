// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_UTILRELEASEDEVICE_TEO_H_
#define FLATBUFFERS_GENERATED_UTILRELEASEDEVICE_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct UtilReleaseDevice;
struct UtilReleaseDeviceBuilder;

struct UtilReleaseDevice FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef UtilReleaseDeviceBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_USER_PUBKEY = 4
  };
  const flatbuffers::Vector<uint8_t> *user_pubkey() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_USER_PUBKEY);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_USER_PUBKEY) &&
           verifier.VerifyVector(user_pubkey()) &&
           verifier.EndTable();
  }
};

struct UtilReleaseDeviceBuilder {
  typedef UtilReleaseDevice Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_user_pubkey(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> user_pubkey) {
    fbb_.AddOffset(UtilReleaseDevice::VT_USER_PUBKEY, user_pubkey);
  }
  explicit UtilReleaseDeviceBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<UtilReleaseDevice> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<UtilReleaseDevice>(end);
    return o;
  }
};

inline flatbuffers::Offset<UtilReleaseDevice> CreateUtilReleaseDevice(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> user_pubkey = 0) {
  UtilReleaseDeviceBuilder builder_(_fbb);
  builder_.add_user_pubkey(user_pubkey);
  return builder_.Finish();
}

inline flatbuffers::Offset<UtilReleaseDevice> CreateUtilReleaseDeviceDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *user_pubkey = nullptr) {
  auto user_pubkey__ = user_pubkey ? _fbb.CreateVector<uint8_t>(*user_pubkey) : 0;
  return teo::CreateUtilReleaseDevice(
      _fbb,
      user_pubkey__);
}

inline const teo::UtilReleaseDevice *GetUtilReleaseDevice(const void *buf) {
  return flatbuffers::GetRoot<teo::UtilReleaseDevice>(buf);
}

inline const teo::UtilReleaseDevice *GetSizePrefixedUtilReleaseDevice(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::UtilReleaseDevice>(buf);
}

inline bool VerifyUtilReleaseDeviceBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::UtilReleaseDevice>(nullptr);
}

inline bool VerifySizePrefixedUtilReleaseDeviceBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::UtilReleaseDevice>(nullptr);
}

inline void FinishUtilReleaseDeviceBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::UtilReleaseDevice> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedUtilReleaseDeviceBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::UtilReleaseDevice> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_UTILRELEASEDEVICE_TEO_H_