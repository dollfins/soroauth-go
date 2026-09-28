// Package awskms signs Soroban authorization entries with an Ed25519 key held
// in AWS KMS.
//
// The package is a separate Go module so applications that do not use AWS do
// not pull the AWS SDK into the root soroauth dependency graph. The AWS
// region, credentials, endpoint, and retry behavior are supplied by the
// caller's aws.Config; this package never hard-codes any of them.
//
// AWS KMS EdDSA signatures are the 64-byte raw Ed25519 signature required by a
// classic Stellar account. ECDSA KMS keys return DER signatures, but they are
// not valid for the classic account signature shape and are rejected by the
// length and verification checks below.
package awskms
