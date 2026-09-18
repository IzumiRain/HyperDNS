// Package integration holds the tests that wire the daemon's real components
// together instead of against doubles.
//
// Every other test here exercises one package in isolation, which is what keeps
// them fast — but it leaves the seams unverified. The DNS handler's access checks
// are satisfied by four separate fake AccessProviders and never once by the
// ClientService that implements them in production, so a fake that drifts from the
// real thing keeps the whole suite green while the resolver refuses paying
// subscribers. That is the failure this package is here to catch.
//
// It is its own package rather than a file inside either side, because an
// integration test has to import both, and putting it in one of them would leave
// that package one edit away from an import cycle it cannot break.
//
// There is deliberately no non-test code here beyond this comment.
package integration
