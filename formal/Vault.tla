----------------------------- MODULE Vault -----------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC
CONSTANTS Requests, Honest, Honest2, Stolen, DeviceOnly, GuardianOnly, Budget,
          RequireGuardian, RequireDevice, RequireWitness, CommitBeforeRelease
VARIABLES disk, witness, history, phase, seq, owner, released, authorized
vars == <<disk, witness, history, phase, seq, owner, released, authorized>>

Initial == [revision |-> 0, next |-> 0, remaining |-> Budget, revoked |-> FALSE]
Device(r) == r \in {Honest, Honest2, DeviceOnly}
Guardian(r) == r \in {Honest, Honest2, GuardianOnly}
CryptographicallyAuthorized(r) == Device(r) /\ Guardian(r)
Evidence(r) == (~RequireDevice \/ Device(r)) /\ (~RequireGuardian \/ Guardian(r))
Consistent == ~RequireWitness \/ disk = witness
Init == /\ disk = Initial /\ witness = Initial /\ history = {Initial}
        /\ phase = [r \in Requests |-> "idle"]
        /\ seq = [r \in Requests |-> 0]
        /\ owner = "none" /\ released = <<>> /\ authorized = {}

Challenge(r) == /\ phase[r] = "idle" /\ owner = "none" /\ Consistent
                /\ ~disk.revoked /\ disk.remaining > 0
                /\ phase' = [phase EXCEPT ![r] = "challenged"]
                /\ seq' = [seq EXCEPT ![r] = disk.next]
                /\ UNCHANGED <<disk,witness,history,owner,released,authorized>>

Begin(r) == /\ phase[r] = "challenged" /\ owner = "none" /\ Consistent
            /\ Evidence(r) /\ ~disk.revoked /\ disk.remaining > 0
            /\ seq[r] = disk.next
            /\ owner' = r /\ phase' = [phase EXCEPT ![r] = "locked"]
            /\ authorized' = IF CryptographicallyAuthorized(r)
                               THEN authorized \cup {r} ELSE authorized
            /\ UNCHANGED <<disk,witness,history,seq,released>>

Reserve(r) == /\ owner = r /\ phase[r] = "locked"
              /\ witness' = [revision |-> witness.revision+1,
                             next |-> disk.next+1, remaining |-> disk.remaining-1,
                             revoked |-> disk.revoked]
              /\ phase' = [phase EXCEPT ![r] = "reserved"]
              /\ UNCHANGED <<disk,history,seq,owner,released,authorized>>

Commit(r) == /\ owner = r /\ phase[r] = "reserved"
             /\ disk' = witness /\ history' = history \cup {witness}
             /\ phase' = [phase EXCEPT ![r] = "committed"]
             /\ owner' = "none"
             /\ UNCHANGED <<witness,seq,released,authorized>>

Release(r) == /\ (IF CommitBeforeRelease THEN phase[r] = "committed"
                   ELSE phase[r] = "committed" \/ (owner = r /\ phase[r] \in {"locked","reserved"}))
              /\ released' = Append(released,[request |-> r, sequence |-> seq[r], committed |-> phase[r] = "committed"])
              /\ phase' = [phase EXCEPT ![r] = "done"] /\ owner' = IF owner = r THEN "none" ELSE owner
              /\ UNCHANGED <<disk,witness,history,seq,authorized>>

Crash(r) == /\ (phase[r] = "committed" \/ (owner = r /\ phase[r] \in {"locked","reserved"}))
            /\ owner' = (IF owner = r THEN "none" ELSE owner)
            /\ phase' = [phase EXCEPT ![r] = "crashed"]
            /\ UNCHANGED <<disk,witness,history,seq,released,authorized>>

Revoke == /\ owner = "none" /\ Consistent /\ ~disk.revoked
          /\ witness' = [witness EXCEPT !.revision = @+1, !.revoked = TRUE]
          /\ disk' = witness' /\ history' = history \cup {witness'}
          /\ UNCHANGED <<phase,seq,owner,released,authorized>>

Rollback == /\ owner = "none" /\ \E old \in history: disk' = old
            /\ UNCHANGED <<witness,history,phase,seq,owner,released,authorized>>

\* Recovery is separately owner-authorized and can only retire. It works even
\* when a crash or rollback left disk inconsistent. No budget is restored.
Quarantine == /\ owner = "none" /\ ~witness.revoked
              /\ witness' = [witness EXCEPT !.revision = @+1,
                              !.remaining = 0, !.revoked = TRUE]
              /\ disk' = witness' /\ history' = history \cup {witness'}
              /\ UNCHANGED <<phase,seq,owner,released,authorized>>

Next == (\E r \in Requests: Challenge(r) \/ Begin(r) \/ Reserve(r) \/ Commit(r) \/ Release(r) \/ Crash(r))
        \/ Revoke \/ Rollback \/ Quarantine
Spec == Init /\ [][Next]_vars
TypeOK == /\ owner \in Requests \cup {"none"}
          /\ disk.remaining \in 0..Budget /\ witness.remaining \in 0..Budget
NoUnauthorizedRelease == \A i \in 1..Len(released): released[i].request \in authorized
NoReplay == \A i,j \in 1..Len(released): i # j => released[i].sequence # released[j].sequence
BoundedRelease == Len(released) <= Budget
CommitBeforeDisclosure == \A i \in 1..Len(released): released[i].committed /\ released[i].sequence < witness.next
=============================================================================
