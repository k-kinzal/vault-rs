--------------------------- MODULE Vault ---------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC
CONSTANTS Requests, Honest, Honest2, DeviceOnly, GuardianOnly, Budget,
          MaxChallenges, MaxAdmin, MaxAttempts,
          RequireGuardian, RequireDevice, RequireWitness, RequireNonce,
          CommitBeforeRelease, RequireIdempotence
VARIABLES disk, witness, history, phase, seq, nonce, owner, planned,
          released, authorized, challengeCount, adminCount, adminPhase,
          attempts, generated
vars == <<disk,witness,history,phase,seq,nonce,owner,planned,released,authorized,
          challengeCount,adminCount,adminPhase,attempts,generated>>
None == "none"
Initial == [revision |-> 0, next |-> 0, remaining |-> Budget, revoked |-> FALSE,
            challenge |-> 0, pending |-> None, lastIssue |-> None]
Device(r) == r \in {Honest, Honest2, DeviceOnly}
Guardian(r) == r \in {Honest, Honest2, GuardianOnly}
IsIssue(r) == r = Honest2
CryptoAuthorized(r) == Device(r) /\ Guardian(r)
Evidence(r) == (~RequireDevice \/ Device(r)) /\ (~RequireGuardian \/ Guardian(r))
Consistent == ~RequireWitness \/ disk = witness
Fresh(r) == disk.challenge # 0 /\ nonce[r] = disk.challenge /\ seq[r] = disk.next
Active == ~disk.revoked /\ disk.remaining > 0 /\ disk.pending = None
Init == /\ disk = Initial /\ witness = Initial /\ history = {Initial}
        /\ phase = [r \in Requests |-> "idle"]
        /\ seq = [r \in Requests |-> 0] /\ nonce = [r \in Requests |-> 0]
        /\ owner = None /\ planned = Initial /\ released = <<>> /\ authorized = {}
        /\ challengeCount = 0 /\ adminCount = 0 /\ adminPhase = "idle"
        /\ attempts = [r \in Requests |-> 0] /\ generated = [r \in Requests |-> 0]

\* Reuse models the cached challenge. Creating a new nonce abstracts expiry;
\* arithmetic validity/freshness of the real clock is a separate Rust theorem.
ChallengeReuse(r) == /\ phase[r] = "idle" /\ owner = None /\ Consistent /\ Active
                     /\ disk.challenge # 0
                     /\ phase' = [phase EXCEPT ![r] = "challenged"]
                     /\ seq' = [seq EXCEPT ![r] = disk.next]
                     /\ nonce' = [nonce EXCEPT ![r] = disk.challenge]
                     /\ UNCHANGED <<disk,witness,history,owner,planned,released,authorized,
                                    challengeCount,adminCount,adminPhase,attempts,generated>>
ChallengeBegin(r) == /\ phase[r] = "idle" /\ owner = None /\ Consistent /\ Active
                     /\ challengeCount < MaxChallenges
                     /\ challengeCount' = challengeCount + 1
                     /\ planned' = [disk EXCEPT !.revision = @+1, !.challenge = challengeCount+1]
                     /\ phase' = [phase EXCEPT ![r] = "challenge-locked"] /\ owner' = r
                     /\ UNCHANGED <<disk,witness,history,seq,nonce,released,authorized,
                                    adminCount,adminPhase,attempts,generated>>
Begin(r) == /\ phase[r] = "challenged" /\ owner = None /\ Consistent /\ Active
            /\ Evidence(r) /\ seq[r] = disk.next /\ (~RequireNonce \/ Fresh(r))
            /\ planned' = [disk EXCEPT !.revision = @+1, !.next = @+1,
                            !.remaining = @-1, !.challenge = 0,
                            !.pending = IF IsIssue(r) THEN r ELSE None]
            /\ owner' = r /\ phase' = [phase EXCEPT ![r] = "locked"]
            /\ authorized' = (IF CryptoAuthorized(r) /\ Fresh(r)
                               THEN authorized \cup {r} ELSE authorized)
            /\ UNCHANGED <<disk,witness,history,seq,nonce,released,challengeCount,
                            adminCount,adminPhase,attempts,generated>>
Reserve(r) == /\ owner = r /\ phase[r] \in {"locked","challenge-locked","finish-locked"}
              /\ witness' = planned
              /\ phase' = [phase EXCEPT ![r] = CASE @ = "locked" -> "reserved"
                                      [] @ = "challenge-locked" -> "challenge-reserved"
                                      [] OTHER -> "finish-reserved"]
              /\ UNCHANGED <<disk,history,seq,nonce,owner,planned,released,authorized,
                             challengeCount,adminCount,adminPhase,attempts,generated>>
Commit(r) == /\ owner = r /\ phase[r] \in {"reserved","challenge-reserved","finish-reserved"}
             /\ disk' = witness /\ history' = history \cup {witness}
             /\ phase' = [phase EXCEPT ![r] = CASE @ = "reserved" -> "committed"
                                     [] @ = "challenge-reserved" -> "challenged"
                                     [] OTHER -> "finished"]
             /\ seq' = (IF phase[r] = "challenge-reserved" THEN [seq EXCEPT ![r] = witness.next] ELSE seq)
             /\ nonce' = (IF phase[r] = "challenge-reserved" THEN [nonce EXCEPT ![r] = witness.challenge] ELSE nonce)
             /\ owner' = None /\ planned' = Initial
             /\ UNCHANGED <<witness,released,authorized,challengeCount,adminCount,adminPhase,attempts,generated>>
ReadReply(r) == /\ ~IsIssue(r)
               /\ (IF CommitBeforeRelease THEN phase[r] = "committed"
                    ELSE phase[r] = "committed" \/ (owner = r /\ phase[r] \in {"locked","reserved"}))
               /\ released' = Append(released,[request |-> r, sequence |-> seq[r],
                                                committed |-> phase[r] = "committed", issue |-> FALSE])
               /\ phase' = [phase EXCEPT ![r] = "done"]
               /\ owner' = (IF owner = r THEN None ELSE owner)
               /\ planned' = (IF owner = r THEN Initial ELSE planned)
               /\ UNCHANGED <<disk,witness,history,seq,nonce,authorized,challengeCount,
                              adminCount,adminPhase,attempts,generated>>
\* Two attempts of ONE operation model concurrent retries. The provider's
\* transaction/advisory-lock contract returns the same encrypted credential.
IssueAttempt(r) == /\ IsIssue(r) /\ phase[r] = "committed" /\ owner = None
                   /\ Consistent /\ ~disk.revoked /\ disk.pending = r
                   /\ attempts[r] < MaxAttempts
                   /\ attempts' = [attempts EXCEPT ![r] = @+1]
                   /\ generated' = [generated EXCEPT ![r] = IF RequireIdempotence THEN 1 ELSE @+1]
                   /\ UNCHANGED <<disk,witness,history,phase,seq,nonce,owner,planned,released,
                                  authorized,challengeCount,adminCount,adminPhase>>
FinishBegin(r) == /\ IsIssue(r) /\ phase[r] = "committed" /\ attempts[r] > 0
                  /\ owner = None /\ Consistent /\ ~disk.revoked /\ disk.pending = r
                  /\ planned' = [disk EXCEPT !.revision = @+1, !.pending = None, !.lastIssue = r]
                  /\ phase' = [phase EXCEPT ![r] = "finish-locked"] /\ owner' = r
                  /\ UNCHANGED <<disk,witness,history,seq,nonce,released,authorized,challengeCount,
                                 adminCount,adminPhase,attempts,generated>>
ReplyCount(r) == Cardinality({i \in 1..Len(released): released[i].request = r})
IssueReply(r) == /\ IsIssue(r) /\ phase[r] = "finished" /\ ReplyCount(r) < attempts[r]
                 /\ released' = Append(released,[request |-> r, sequence |-> seq[r], committed |-> TRUE, issue |-> TRUE])
                 /\ UNCHANGED <<disk,witness,history,phase,seq,nonce,owner,planned,authorized,
                                challengeCount,adminCount,adminPhase,attempts,generated>>
Resume(r) == /\ IsIssue(r) /\ phase[r] = "crashed" /\ owner = None /\ Consistent
             /\ ~disk.revoked /\ disk.pending = r
             /\ phase' = [phase EXCEPT ![r] = "committed"]
             /\ UNCHANGED <<disk,witness,history,seq,nonce,owner,planned,released,authorized,
                            challengeCount,adminCount,adminPhase,attempts,generated>>
Crash(r) == /\ (phase[r] \in {"committed","challenged","finished"}
                 \/ (owner = r /\ phase[r] \in {"locked","reserved","challenge-locked","challenge-reserved","finish-locked","finish-reserved"}))
            /\ owner' = (IF owner = r THEN None ELSE owner)
            /\ planned' = (IF owner = r THEN Initial ELSE planned)
            /\ phase' = [phase EXCEPT ![r] = "crashed"]
            /\ UNCHANGED <<disk,witness,history,seq,nonce,released,authorized,challengeCount,
                           adminCount,adminPhase,attempts,generated>>

\* Only separately authorized administrator commands are admitted by this
\* model; their signature/input checkpoint checks are primitive contracts.
AdminBegin(kind) == /\ owner = None /\ adminPhase = "idle" /\ adminCount < MaxAdmin
                    /\ (IF kind = "revoke" THEN Consistent /\ ~disk.revoked ELSE TRUE)
                    /\ planned' = (IF kind = "revoke"
                         THEN [disk EXCEPT !.revision = @+1, !.revoked = TRUE, !.challenge = 0, !.pending = None]
                         ELSE [revision |-> witness.revision+1, next |-> Budget+1, remaining |-> 0,
                               revoked |-> TRUE, challenge |-> 0, pending |-> None, lastIssue |-> None])
                    /\ owner' = kind /\ adminPhase' = "locked" /\ adminCount' = adminCount+1
                    /\ UNCHANGED <<disk,witness,history,phase,seq,nonce,released,authorized,
                                   challengeCount,attempts,generated>>
AdminReserve == /\ owner \in {"revoke","quarantine"} /\ adminPhase = "locked"
                /\ witness' = planned /\ adminPhase' = "reserved"
                /\ UNCHANGED <<disk,history,phase,seq,nonce,owner,planned,released,authorized,
                               challengeCount,adminCount,attempts,generated>>
AdminCommit == /\ owner \in {"revoke","quarantine"} /\ adminPhase = "reserved"
               /\ disk' = witness /\ history' = history \cup {witness}
               /\ owner' = None /\ adminPhase' = "idle" /\ planned' = Initial
               /\ UNCHANGED <<witness,phase,seq,nonce,released,authorized,challengeCount,
                              adminCount,attempts,generated>>
AdminCrash == /\ owner \in {"revoke","quarantine"} /\ adminPhase \in {"locked","reserved"}
              /\ owner' = None /\ adminPhase' = "idle" /\ planned' = Initial
              /\ UNCHANGED <<disk,witness,history,phase,seq,nonce,released,authorized,
                             challengeCount,adminCount,attempts,generated>>
Rollback == /\ owner = None /\ \E old \in history: disk' = old
            /\ UNCHANGED <<witness,history,phase,seq,nonce,owner,planned,released,authorized,
                           challengeCount,adminCount,adminPhase,attempts,generated>>
Next == (\E r \in Requests: ChallengeReuse(r) \/ ChallengeBegin(r) \/ Begin(r) \/ Reserve(r) \/ Commit(r)
                          \/ ReadReply(r) \/ IssueAttempt(r) \/ FinishBegin(r) \/ IssueReply(r) \/ Resume(r) \/ Crash(r))
        \/ (\E kind \in {"revoke","quarantine"}: AdminBegin(kind))
        \/ AdminReserve \/ AdminCommit \/ AdminCrash \/ Rollback
Spec == Init /\ [][Next]_vars
TypeOK == /\ owner \in Requests \cup {None,"revoke","quarantine"}
          /\ disk.remaining \in 0..Budget /\ witness.remaining \in 0..Budget
          /\ disk.next \in 0..(Budget+1) /\ witness.next \in 0..(Budget+1)
          /\ challengeCount \in 0..MaxChallenges /\ adminCount \in 0..MaxAdmin
          /\ attempts \in [Requests -> 0..MaxAttempts] /\ generated \in [Requests -> 0..MaxAttempts]
          /\ phase \in [Requests -> {"idle","challenged","challenge-locked","challenge-reserved","locked","reserved","committed","finish-locked","finish-reserved","finished","done","crashed"}]
NoUnauthorizedRelease == \A i \in 1..Len(released): released[i].request \in authorized
\* Retries of one issued lease are allowed; different operations cannot reuse
\* sequence numbers, and static reads can never be replayed.
NoReplay == \A i,j \in 1..Len(released): i # j /\ released[i].sequence = released[j].sequence
                => released[i].request = released[j].request /\ released[i].issue /\ released[j].issue
DistinctReleased == {released[i].request : i \in 1..Len(released)}
BoundedRelease == Cardinality(DistinctReleased) <= Budget
CommitBeforeDisclosure == \A i \in 1..Len(released): released[i].committed /\ released[i].sequence < witness.next
OneCredentialPerOperation == \A r \in Requests: generated[r] <= 1
\* Expected-failing coverage queries, run separately: these demonstrate the
\* finite graph admits useful static release, duplicate replies for one issue,
\* and quarantine after an administrator's witness-reserved/DB-not-committed crash.
NoHonestStaticRelease == ~ (\E i \in 1..Len(released): released[i].request = Honest)
NoIdenticalIssueRetry == ReplyCount(Honest2) < 2
NoRecoveredAdminCrash == ~ (disk = witness /\ disk.revoked /\ disk.next = Budget+1
                           /\ disk.revision = 2 /\ Cardinality(history) = 2 /\ adminCount = 2)
=============================================================================
