;; UtiliProof Protocol - Privacy-First Utilities Management
;; A decentralized verification network for utility consumption data with zero-knowledge proofs

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROOF (err u101))
(define-constant ERR-PROPERTY-NOT-FOUND (err u102))
(define-constant ERR-UTILITY-NOT-REGISTERED (err u103))
(define-constant ERR-INVALID-COMMITMENT (err u104))
(define-constant ERR-EXPIRED-PROOF (err u105))
(define-constant ERR-INSUFFICIENT-REPUTATION (err u106))
(define-constant ERR-ALREADY-EXISTS (err u107))
(define-constant ERR-INVALID-RANGE (err u108))

;; Utility types
(define-constant UTILITY-ELECTRICITY u1)
(define-constant UTILITY-WATER u2)
(define-constant UTILITY-GAS u3)
(define-constant UTILITY-INTERNET u4)

;; Proof types
(define-constant PROOF-PAYMENT-HISTORY u1)
(define-constant PROOF-CONSUMPTION-RANGE u2)
(define-constant PROOF-EFFICIENCY-SCORE u3)
(define-constant PROOF-CARBON-FOOTPRINT u4)

;; Data Variables
(define-data-var protocol-fee uint u100) ;; 1% in basis points
(define-data-var min-reputation-score uint u500)
(define-data-var proof-validity-period uint u4320) ;; ~30 days in blocks

;; Data Maps

;; Property Registry - stores unlinkable property identifiers
(define-map properties
    { property-id: (buff 32) }
    {
        owner: principal,
        reputation-score: uint,
        total-verifications: uint,
        creation-block: uint,
        last-update: uint,
        is-active: bool
    }
)

;; Utility Company Registry
(define-map utility-companies
    { company-id: principal }
    {
        name: (string-ascii 50),
        utility-types: (list 10 uint),
        is-verified: bool,
        total-commitments: uint,
        registration-block: uint
    }
)

;; Consumption Commitments - encrypted ranges submitted by utility companies
(define-map consumption-commitments
    { 
        commitment-id: (buff 32),
        property-id: (buff 32),
        utility-type: uint
    }
    {
        company: principal,
        commitment-hash: (buff 32), ;; Hash of encrypted consumption range
        period-start: uint,
        period-end: uint,
        verification-count: uint,
        is-valid: bool
    }
)

;; Utility Credential Fragments - privacy-preserving credentials
(define-map credential-fragments
    {
        fragment-id: (buff 32),
        property-id: (buff 32)
    }
    {
        utility-type: uint,
        credential-hash: (buff 32),
        issuer: principal,
        issue-block: uint,
        expiry-block: uint,
        proof-type: uint
    }
)

;; Zero-Knowledge Proofs - verification without revealing data
(define-map zk-proofs
    {
        proof-id: (buff 32)
    }
    {
        property-id: (buff 32),
        proof-type: uint,
        proof-hash: (buff 32), ;; Hash of ZK proof data
        verifier: (optional principal),
        creation-block: uint,
        expiry-block: uint,
        is-verified: bool,
        verification-block: (optional uint)
    }
)

;; Property Reputation Registry - unlinkable trust scores
(define-map reputation-events
    {
        event-id: (buff 32),
        property-id: (buff 32)
    }
    {
        event-type: uint, ;; 1=positive, 2=negative, 3=neutral
        reputation-delta: int,
        source: principal,
        block-height: uint,
        description: (string-ascii 100)
    }
)

;; Efficiency Incentives - tokenized rewards
(define-map efficiency-rewards
    {
        property-id: (buff 32),
        period: uint
    }
    {
        efficiency-score: uint,
        reward-amount: uint,
        is-claimed: bool,
        claim-block: (optional uint)
    }
)

;; Temporal Proof Registry - time-based consumption verification
(define-map temporal-proofs
    {
        temporal-id: (buff 32),
        property-id: (buff 32)
    }
    {
        start-period: uint,
        end-period: uint,
        trend-hash: (buff 32), ;; Hash of consumption trend without revealing spikes
        baseline-commitment: (buff 32),
        variance-proof: (buff 32)
    }
)

;; Access Control Lists - who can verify what
(define-map verification-permissions
    {
        property-id: (buff 32),
        verifier: principal
    }
    {
        allowed-proof-types: (list 10 uint),
        granted-block: uint,
        expiry-block: uint,
        is-revoked: bool
    }
)

;; Read-Only Functions

(define-read-only (get-property-info (property-id (buff 32)))
    (map-get? properties { property-id: property-id })
)

(define-read-only (get-property-reputation (property-id (buff 32)))
    (ok (get reputation-score (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND)))
)

(define-read-only (get-commitment (commitment-id (buff 32)) (property-id (buff 32)) (utility-type uint))
    (map-get? consumption-commitments { 
        commitment-id: commitment-id,
        property-id: property-id,
        utility-type: utility-type
    })
)

(define-read-only (get-credential-fragment (fragment-id (buff 32)) (property-id (buff 32)))
    (map-get? credential-fragments {
        fragment-id: fragment-id,
        property-id: property-id
    })
)

(define-read-only (get-zk-proof (proof-id (buff 32)))
    (map-get? zk-proofs { proof-id: proof-id })
)

(define-read-only (is-proof-valid (proof-id (buff 32)))
    (let (
        (proof (unwrap! (map-get? zk-proofs { proof-id: proof-id }) (err false)))
        (expiry (get expiry-block proof))
    )
        (ok (and 
            (get is-verified proof)
            (>= expiry block-height)
        ))
    )
)

(define-read-only (get-utility-company (company-id principal))
    (map-get? utility-companies { company-id: company-id })
)

(define-read-only (check-verification-permission (property-id (buff 32)) (verifier principal) (proof-type uint))
    (match (map-get? verification-permissions {
        property-id: property-id,
        verifier: verifier
    })
        permission (ok (and
            (not (get is-revoked permission))
            (>= (get expiry-block permission) block-height)
            (is-some (index-of (get allowed-proof-types permission) proof-type))
        ))
        (ok false)
    )
)

(define-read-only (get-efficiency-reward (property-id (buff 32)) (period uint))
    (map-get? efficiency-rewards {
        property-id: property-id,
        period: period
    })
)

(define-read-only (get-temporal-proof (temporal-id (buff 32)) (property-id (buff 32)))
    (map-get? temporal-proofs {
        temporal-id: temporal-id,
        property-id: property-id
    })
)

;; Public Functions

;; Register a new property with unlinkable identifier
(define-public (register-property (property-id (buff 32)))
    (let (
        (existing (map-get? properties { property-id: property-id }))
    )
        (asserts! (is-none existing) ERR-ALREADY-EXISTS)
        (ok (map-set properties
            { property-id: property-id }
            {
                owner: tx-sender,
                reputation-score: u1000, ;; Start with neutral reputation
                total-verifications: u0,
                creation-block: block-height,
                last-update: block-height,
                is-active: true
            }
        ))
    )
)

;; Register a utility company
(define-public (register-utility-company 
    (name (string-ascii 50))
    (utility-types (list 10 uint)))
    (let (
        (existing (map-get? utility-companies { company-id: tx-sender }))
    )
        (asserts! (is-none existing) ERR-ALREADY-EXISTS)
        (ok (map-set utility-companies
            { company-id: tx-sender }
            {
                name: name,
                utility-types: utility-types,
                is-verified: false, ;; Requires admin verification
                total-commitments: u0,
                registration-block: block-height
            }
        ))
    )
)

;; Submit consumption commitment (utility company only)
(define-public (submit-consumption-commitment
    (commitment-id (buff 32))
    (property-id (buff 32))
    (utility-type uint)
    (commitment-hash (buff 32))
    (period-start uint)
    (period-end uint))
    (let (
        (company (unwrap! (map-get? utility-companies { company-id: tx-sender }) ERR-NOT-AUTHORIZED))
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (get is-verified company) ERR-NOT-AUTHORIZED)
        (asserts! (< period-start period-end) ERR-INVALID-RANGE)
        (ok (map-set consumption-commitments
            {
                commitment-id: commitment-id,
                property-id: property-id,
                utility-type: utility-type
            }
            {
                company: tx-sender,
                commitment-hash: commitment-hash,
                period-start: period-start,
                period-end: period-end,
                verification-count: u0,
                is-valid: true
            }
        ))
    )
)

;; Issue utility credential fragment
(define-public (issue-credential-fragment
    (fragment-id (buff 32))
    (property-id (buff 32))
    (utility-type uint)
    (credential-hash (buff 32))
    (proof-type uint)
    (validity-blocks uint))
    (let (
        (company (unwrap! (map-get? utility-companies { company-id: tx-sender }) ERR-NOT-AUTHORIZED))
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (get is-verified company) ERR-NOT-AUTHORIZED)
        (ok (map-set credential-fragments
            {
                fragment-id: fragment-id,
                property-id: property-id
            }
            {
                utility-type: utility-type,
                credential-hash: credential-hash,
                issuer: tx-sender,
                issue-block: block-height,
                expiry-block: (+ block-height validity-blocks),
                proof-type: proof-type
            }
        ))
    )
)

;; Generate zero-knowledge proof
(define-public (generate-zk-proof
    (proof-id (buff 32))
    (property-id (buff 32))
    (proof-type uint)
    (proof-hash (buff 32))
    (validity-blocks uint))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (is-eq (get owner property) tx-sender) ERR-NOT-AUTHORIZED)
        (asserts! (get is-active property) ERR-NOT-AUTHORIZED)
        (ok (map-set zk-proofs
            { proof-id: proof-id }
            {
                property-id: property-id,
                proof-type: proof-type,
                proof-hash: proof-hash,
                verifier: none,
                creation-block: block-height,
                expiry-block: (+ block-height validity-blocks),
                is-verified: false,
                verification-block: none
            }
        ))
    )
)

;; Verify zero-knowledge proof (verifier)
(define-public (verify-zk-proof
    (proof-id (buff 32))
    (verification-result bool))
    (let (
        (proof (unwrap! (map-get? zk-proofs { proof-id: proof-id }) ERR-INVALID-PROOF))
        (property-id (get property-id proof))
    )
        (asserts! (< block-height (get expiry-block proof)) ERR-EXPIRED-PROOF)
        (asserts! (unwrap! (check-verification-permission property-id tx-sender (get proof-type proof)) ERR-NOT-AUTHORIZED) ERR-NOT-AUTHORIZED)
        
        (map-set zk-proofs
            { proof-id: proof-id }
            (merge proof {
                is-verified: verification-result,
                verifier: (some tx-sender),
                verification-block: (some block-height)
            })
        )
        
        ;; Update property reputation on successful verification
        (if verification-result
            (try! (update-reputation property-id u1 50 tx-sender "ZK proof verified"))
            (try! (update-reputation property-id u2 -25 tx-sender "ZK proof failed"))
        )
        
        (ok verification-result)
    )
)

;; Grant verification permission to a third party
(define-public (grant-verification-permission
    (property-id (buff 32))
    (verifier principal)
    (allowed-proof-types (list 10 uint))
    (validity-blocks uint))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (is-eq (get owner property) tx-sender) ERR-NOT-AUTHORIZED)
        (ok (map-set verification-permissions
            {
                property-id: property-id,
                verifier: verifier
            }
            {
                allowed-proof-types: allowed-proof-types,
                granted-block: block-height,
                expiry-block: (+ block-height validity-blocks),
                is-revoked: false
            }
        ))
    )
)

;; Revoke verification permission
(define-public (revoke-verification-permission
    (property-id (buff 32))
    (verifier principal))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
        (permission (unwrap! (map-get? verification-permissions {
            property-id: property-id,
            verifier: verifier
        }) ERR-NOT-AUTHORIZED))
    )
        (asserts! (is-eq (get owner property) tx-sender) ERR-NOT-AUTHORIZED)
        (ok (map-set verification-permissions
            {
                property-id: property-id,
                verifier: verifier
            }
            (merge permission { is-revoked: true })
        ))
    )
)

;; Submit temporal proof for consumption trends
(define-public (submit-temporal-proof
    (temporal-id (buff 32))
    (property-id (buff 32))
    (start-period uint)
    (end-period uint)
    (trend-hash (buff 32))
    (baseline-commitment (buff 32))
    (variance-proof (buff 32)))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (is-eq (get owner property) tx-sender) ERR-NOT-AUTHORIZED)
        (asserts! (< start-period end-period) ERR-INVALID-RANGE)
        (ok (map-set temporal-proofs
            {
                temporal-id: temporal-id,
                property-id: property-id
            }
            {
                start-period: start-period,
                end-period: end-period,
                trend-hash: trend-hash,
                baseline-commitment: baseline-commitment,
                variance-proof: variance-proof
            }
        ))
    )
)

;; Award efficiency incentive
(define-public (award-efficiency-incentive
    (property-id (buff 32))
    (period uint)
    (efficiency-score uint)
    (reward-amount uint))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (or (is-eq tx-sender CONTRACT-OWNER) (is-some (map-get? utility-companies { company-id: tx-sender }))) ERR-NOT-AUTHORIZED)
        (ok (map-set efficiency-rewards
            {
                property-id: property-id,
                period: period
            }
            {
                efficiency-score: efficiency-score,
                reward-amount: reward-amount,
                is-claimed: false,
                claim-block: none
            }
        ))
    )
)

;; Claim efficiency reward
(define-public (claim-efficiency-reward
    (property-id (buff 32))
    (period uint))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
        (reward (unwrap! (map-get? efficiency-rewards {
            property-id: property-id,
            period: period
        }) ERR-PROPERTY-NOT-FOUND))
    )
        (asserts! (is-eq (get owner property) tx-sender) ERR-NOT-AUTHORIZED)
        (asserts! (not (get is-claimed reward)) ERR-ALREADY-EXISTS)
        
        (map-set efficiency-rewards
            {
                property-id: property-id,
                period: period
            }
            (merge reward {
                is-claimed: true,
                claim-block: (some block-height)
            })
        )
        
        ;; Transfer reward (implementation depends on token standard)
        (ok (get reward-amount reward))
    )
)

;; Internal function to update reputation
(define-private (update-reputation 
    (property-id (buff 32))
    (event-type uint)
    (delta int)
    (source principal)
    (description (string-ascii 100)))
    (let (
        (property (unwrap! (map-get? properties { property-id: property-id }) ERR-PROPERTY-NOT-FOUND))
        (current-score (get reputation-score property))
        (new-score (if (> delta 0)
            (+ current-score (to-uint delta))
            (if (> current-score (to-uint (* delta -1)))
                (- current-score (to-uint (* delta -1)))
                u0
            )
        ))
        (event-id (sha256 (concat (concat property-id (unwrap-panic (to-consensus-buff? block-height))) (unwrap-panic (to-consensus-buff? source)))))
    )
        (map-set properties
            { property-id: property-id }
            (merge property {
                reputation-score: new-score,
                last-update: block-height,
                total-verifications: (+ (get total-verifications property) u1)
            })
        )
        
        (map-set reputation-events
            {
                event-id: event-id,
                property-id: property-id
            }
            {
                event-type: event-type,
                reputation-delta: delta,
                source: source,
                block-height: block-height,
                description: description
            }
        )
        (ok new-score)
    )
)

;; Admin Functions

(define-public (verify-utility-company (company-id principal))
    (let (
        (company (unwrap! (map-get? utility-companies { company-id: company-id }) ERR-UTILITY-NOT-REGISTERED))
    )
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (ok (map-set utility-companies
            { company-id: company-id }
            (merge company { is-verified: true })
        ))
    )
)

(define-public (set-protocol-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (ok (var-set protocol-fee new-fee))
    )
)

(define-public (set-min-reputation (new-min uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (ok (var-set min-reputation-score new-min))
    )
)

;; Initialize contract
(begin
    (print "UtiliProof Protocol initialized")
)
