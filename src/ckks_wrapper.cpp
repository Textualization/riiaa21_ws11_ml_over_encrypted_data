// @file ckks_wrapper.cpp CKKS wrapper for the python wrapper to PALISADE
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2020, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <vector>

#include "ckks_wrapper.h"

using namespace lbcrypto;

namespace pycrypto {

/**
 * Converter from pylist to vector<std::complex<double>> with real parts from
 * pylist and imag parts zero
 */
std::vector<std::complex<double>> pythonListToCppVector(
    const boost::python::list &pylist) {
  std::vector<std::complex<double>> cppVector;
  for (unsigned int i = 0; i < len(pylist); i++) {
    double val = boost::python::extract<double>(pylist[i]);
    cppVector.push_back(std::complex<double>(val, 0.));
  }
  return cppVector;
}

CiphertextInterfaceType::CiphertextInterfaceType() {
  m_ciphertext = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>());
}

CiphertextInterfaceType::CiphertextInterfaceType(
    Ciphertext<DCRTPoly> ciphertext) {
  m_ciphertext = ciphertext;
}

CiphertextInterfaceType::~CiphertextInterfaceType() {}

const CiphertextImpl<DCRTPoly> &CiphertextInterfaceType::GetCiphertext() const {
  return *m_ciphertext;
}

CKKSwrapper::CKKSwrapper() {}

void CKKSwrapper::KeyGen(uint32_t multDepth, uint32_t scaleFactorBits,
                         uint32_t batchSize) {
  m_cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
      multDepth, scaleFactorBits, batchSize, HEStd_128_classic);
  m_cc->Enable(ENCRYPTION);
  m_cc->Enable(SHE);
  m_keys = m_cc->KeyGen();
  m_cc->EvalMultKeyGen(m_keys.secretKey);
  m_cc->EvalSumKeyGen(m_keys.secretKey);
}

CiphertextInterfaceType *CKKSwrapper::Encrypt(
    const boost::python::list &pyvals) {
  std::vector<std::complex<double>> vals = pythonListToCppVector(pyvals);
  shared_ptr<PlaintextImpl> ptxt = m_cc->MakeCKKSPackedPlaintext(vals);
  Ciphertext<DCRTPoly> ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);
  return new CiphertextInterfaceType(ctxt);
}

vector<std::complex<double>> CKKSwrapper::Decrypt(
    const CiphertextInterfaceType &ciphertextInterface) {
  const CiphertextImpl<DCRTPoly> &ct = ciphertextInterface.GetCiphertext();
  Ciphertext<DCRTPoly> ciphertext(new CiphertextImpl<DCRTPoly>(ct));
  Plaintext result;
  m_cc->Decrypt(m_keys.secretKey, ciphertext, &result);
  result->SetLength(result->GetElementRingDimension() / 2);
  return result->GetCKKSPackedValue();
}

CiphertextInterfaceType *CKKSwrapper::EvalAdd(
    const CiphertextInterfaceType &ciphertext1,
    const CiphertextInterfaceType &ciphertext2) {
  auto cipher1 = Ciphertext<DCRTPoly>(
      new CiphertextImpl<DCRTPoly>(ciphertext1.GetCiphertext()));
  auto cipher2 = Ciphertext<DCRTPoly>(
      new CiphertextImpl<DCRTPoly>(ciphertext2.GetCiphertext()));

  auto cipherAdd = m_cc->EvalAdd(cipher1, cipher2);
  return new CiphertextInterfaceType(cipherAdd);
}

CiphertextInterfaceType *CKKSwrapper::EvalMult(
    const CiphertextInterfaceType &ciphertext1,
    const CiphertextInterfaceType &ciphertext2) {
  auto cipher1 = Ciphertext<DCRTPoly>(
      new CiphertextImpl<DCRTPoly>(ciphertext1.GetCiphertext()));
  auto cipher2 = Ciphertext<DCRTPoly>(
      new CiphertextImpl<DCRTPoly>(ciphertext2.GetCiphertext()));

  auto cipherMult = m_cc->EvalMult(cipher1, cipher2);
  return new CiphertextInterfaceType(cipherMult);
}

CiphertextInterfaceType *CKKSwrapper::EvalMultConst(
    const CiphertextInterfaceType &ciphertext1,
    const boost::python::list &pylist) {
  auto cipher1 = Ciphertext<DCRTPoly>(
      new CiphertextImpl<DCRTPoly>(ciphertext1.GetCiphertext()));
  std::vector<std::complex<double>> vals = pythonListToCppVector(pylist);
  Plaintext plain2 = m_cc->MakeCKKSPackedPlaintext(vals);
  auto cipherMult = m_cc->EvalMult(cipher1, plain2);
  return new CiphertextInterfaceType(cipherMult);
}

CiphertextInterfaceType *CKKSwrapper::EvalSum(
    const CiphertextInterfaceType &ciphertext, usint batch_size) {
  auto cipher = Ciphertext<DCRTPoly>(
      new CiphertextImpl<DCRTPoly>(ciphertext.GetCiphertext()));
  auto cipherSum = m_cc->EvalSum(cipher, batch_size);
  return new CiphertextInterfaceType(cipherSum);
}

}  // namespace pycrypto
