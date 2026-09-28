pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Generic operation codes: EQ=1, LE=2, GE=3, IN=4.
// Generic disclosure modes: REVEAL=1, PREDICATE=2.

template MerkleMembership2() {
    signal input leaf;
    signal input siblings[2];
    signal input indices[2];
    signal input root;
    signal hashes[3];
    signal left[2];
    signal right[2];
    component h[2];
    hashes[0] <== leaf;
    for (var i = 0; i < 2; i++) {
        indices[i] * (indices[i] - 1) === 0;
        left[i] <== hashes[i] + indices[i] * (siblings[i] - hashes[i]);
        right[i] <== siblings[i] + indices[i] * (hashes[i] - siblings[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== left[i];
        h[i].inputs[1] <== right[i];
        hashes[i + 1] <== h[i].out;
    }
    hashes[2] === root;
}

template GenericAssertions() {
    signal input root;

    // Public AssertionSpec arrays. targets[i] contains up to two IN members.
    signal input assertionSubject[4];
    signal input assertionField[4];
    signal input assertionOp[4];
    signal input assertionTargets[4][2];
    signal input assertionTargetCount[4];
    signal input assertionMode[4];
    signal input revealedValue[4];

    // Private Evidence tuple:
    // [schemaID, subjectID, fieldID, typeTag, value, timestamp, sourceGroupID]
    signal input evidence[4][7];
    signal input pathElements[4][2];
    signal input pathIndices[4][2];

    component leafHash[4];
    component membership[4];
    component opEq[4][4];
    component valueEqTarget[4][2];
    component le[4];
    component ge[4];
    component modeReveal[4];
    signal secondEnabled[4];
    signal secondMatch[4];
    signal inResult[4];
    signal opResult[4][4];
    signal evalResult[4];

    for (var i = 0; i < 4; i++) {
        leafHash[i] = Poseidon(7);
        for (var j = 0; j < 7; j++) {
            leafHash[i].inputs[j] <== evidence[i][j];
        }
        membership[i] = MerkleMembership2();
        membership[i].leaf <== leafHash[i].out;
        membership[i].root <== root;
        for (var p = 0; p < 2; p++) {
            membership[i].siblings[p] <== pathElements[i][p];
            membership[i].indices[p] <== pathIndices[i][p];
        }

        evidence[i][1] === assertionSubject[i];
        evidence[i][2] === assertionField[i];

        for (var op = 0; op < 4; op++) {
            opEq[i][op] = IsEqual();
            opEq[i][op].in[0] <== assertionOp[i];
            opEq[i][op].in[1] <== op + 1;
        }
        opEq[i][0].out + opEq[i][1].out + opEq[i][2].out + opEq[i][3].out === 1;

        for (var t = 0; t < 2; t++) {
            valueEqTarget[i][t] = IsEqual();
            valueEqTarget[i][t].in[0] <== evidence[i][4];
            valueEqTarget[i][t].in[1] <== assertionTargets[i][t];
        }
        (assertionTargetCount[i] - 1) * (assertionTargetCount[i] - 2) === 0;
        secondEnabled[i] <== assertionTargetCount[i] - 1;
        secondMatch[i] <== valueEqTarget[i][1].out * secondEnabled[i];
        inResult[i] <== valueEqTarget[i][0].out + secondMatch[i] -
            valueEqTarget[i][0].out * secondMatch[i];

        le[i] = LessThan(32);
        le[i].in[0] <== evidence[i][4];
        le[i].in[1] <== assertionTargets[i][0] + 1;
        ge[i] = LessThan(32);
        ge[i].in[0] <== assertionTargets[i][0];
        ge[i].in[1] <== evidence[i][4] + 1;

        opResult[i][0] <== opEq[i][0].out * valueEqTarget[i][0].out;
        opResult[i][1] <== opEq[i][1].out * le[i].out;
        opResult[i][2] <== opEq[i][2].out * ge[i].out;
        opResult[i][3] <== opEq[i][3].out * inResult[i];
        evalResult[i] <== opResult[i][0] + opResult[i][1] + opResult[i][2] + opResult[i][3];
        evalResult[i] === 1;

        modeReveal[i] = IsEqual();
        modeReveal[i].in[0] <== assertionMode[i];
        modeReveal[i].in[1] <== 1;
        (assertionMode[i] - 1) * (assertionMode[i] - 2) === 0;
        assertionMode[i] === 1 + (1 - modeReveal[i].out);
        modeReveal[i].out * (evidence[i][4] - revealedValue[i]) === 0;
        (1 - modeReveal[i].out) * revealedValue[i] === 0;
    }
}

component main {public [root, assertionSubject, assertionField, assertionOp,
                        assertionTargets, assertionTargetCount, assertionMode,
                        revealedValue]} = GenericAssertions();
