pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mimcsponge.circom";

// Experiment 2 only: domain-separated MiMC, BN254, 220 rounds.
// A record is [oid, created, validFrom, validUntil, risk, lifecycle, assessment].
// This modular cost profile is separate from Experiment 1 and the Nova design.
template Hash(N, domain) {
    signal input in[N]; signal output out;
    component h = MiMCSponge(N, 220, 1);
    h.k <== domain;
    for (var i=0; i<N; i++) h.ins[i] <== in[i];
    out <== h.outs[0];
}
template Record() {
    signal input fields[7]; signal output digest;
    component bits[7]; component h=Hash(7, 201);
    for(var j=0;j<7;j++) {
        bits[j]=Num2Bits(32); bits[j].in <== fields[j];
        h.in[j] <== fields[j];
    }
    component life=LessEqThan(32); life.in[0]<==fields[5];life.in[1]<==2;life.out===1;
    component assessment=LessEqThan(32);assessment.in[0]<==fields[6];assessment.in[1]<==2;assessment.out===1;
    digest <== h.out;
}
template Path(D) {
    signal input leaf; signal input index; signal input siblings[D];
    signal output root;
    component bits=Num2Bits(D);bits.in<==index;
    component hashes[D];signal state[D+1];signal left[D];signal right[D];
    state[0]<==leaf;
    for(var i=0;i<D;i++) {
        left[i]<==state[i]+bits.out[i]*(siblings[i]-state[i]);
        right[i]<==siblings[i]+bits.out[i]*(state[i]-siblings[i]);
        hashes[i]=Hash(2,202);hashes[i].in[0]<==left[i];hashes[i].in[1]<==right[i];
        state[i+1]<==hashes[i].out;
    }
    root<==state[D];
}
template Subtree(N) {
    signal input leaves[N];signal output root;
    signal nodes[2*N-1];component hashes[N-1];
    for(var i=0;i<N;i++)nodes[N-1+i]<==leaves[i];
    for(var i=N-2;i>=0;i--) {
        hashes[i]=Hash(2,202);hashes[i].in[0]<==nodes[2*i+1];hashes[i].in[1]<==nodes[2*i+2];
        nodes[i]<==hashes[i].out;
    }
    root<==nodes[0];
}
template Commitment(N) {
    signal input records[N][7];signal input salt;
    signal input context[4]; // nonce, authenticated time root, lower, upper
    signal output digest;
    component h=Hash(7*N+5,203);
    for(var i=0;i<4;i++)h.in[i]<==context[i];
    h.in[4]<==salt;
    for(var i=0;i<N;i++)for(var j=0;j<7;j++)h.in[5+7*i+j]<==records[i][j];
    digest<==h.out;
}

// Real batched CREATE transitions over aligned, initially empty subtrees.
// Authenticates old/new log AND state roots; this is not recursive Nova IVC.
template Psi(N,D) {
    var H=0;var size=N;while(size>1){H++;size=size\2;}
    assert(2**H==N);assert(D>H);
    signal input oldSeq;signal input newSeq;signal input blockIndex;
    signal input oldLogRoot;signal input newLogRoot;
    signal input oldStateRoot;signal input newStateRoot;
    signal input records[N][7];
    signal input logSiblings[D-H];signal input stateSiblings[D-H];
    component seqBits=Num2Bits(32);seqBits.in<==oldSeq;
    component nextBits=Num2Bits(32);nextBits.in<==newSeq;
    oldSeq===blockIndex*N;newSeq===oldSeq+N;
    component record[N];component event[N];component ordered[N-1];
    component logTree=Subtree(N);component stateTree=Subtree(N);
    component empty[H];signal emptyRoot[H+1];emptyRoot[0]<==0;
    for(var h=0;h<H;h++) {
        empty[h]=Hash(2,202);empty[h].in[0]<==emptyRoot[h];empty[h].in[1]<==emptyRoot[h];
        emptyRoot[h+1]<==empty[h].out;
    }
    for(var i=0;i<N;i++) {
        record[i]=Record();for(var j=0;j<7;j++)record[i].fields[j]<==records[i][j];
        records[i][0]===oldSeq+i+1;records[i][5]===1;
        if(i>0) {
            // CREATE stream in this workload is ordered by creation time.
            ordered[i-1]=LessEqThan(32);
            ordered[i-1].in[0]<==records[i-1][1];ordered[i-1].in[1]<==records[i][1];ordered[i-1].out===1;
        }
        event[i]=Hash(2,204);event[i].in[0]<==oldSeq+i+1;event[i].in[1]<==record[i].digest;
        logTree.leaves[i]<==event[i].out;stateTree.leaves[i]<==record[i].digest;
    }
    component oldLog=Path(D-H);component newLog=Path(D-H);
    component oldState=Path(D-H);component newState=Path(D-H);
    oldLog.leaf<==emptyRoot[H];oldState.leaf<==emptyRoot[H];
    newLog.leaf<==logTree.root;newState.leaf<==stateTree.root;
    oldLog.index<==blockIndex;newLog.index<==blockIndex;
    oldState.index<==blockIndex;newState.index<==blockIndex;
    for(var h=0;h<D-H;h++) {
        oldLog.siblings[h]<==logSiblings[h];newLog.siblings[h]<==logSiblings[h];
        oldState.siblings[h]<==stateSiblings[h];newState.siblings[h]<==stateSiblings[h];
    }
    oldLog.root===oldLogRoot;newLog.root===newLogRoot;
    oldState.root===oldStateRoot;newState.root===newStateRoot;
}

// Conditional complete range query: the authenticated index is sorted by
// (created, oid), as maintained by the state updater. All N+2 paths are real.
template GammaQ(N,D) {
    signal input timeRoot;signal input commitment;signal input nonce;
    signal input lower;signal input upper;signal input startIndex;
    signal input records[N][7];signal input salt;
    signal input boundary[2][7];signal input paths[N+2][D];
    component scalarBits[2];scalarBits[0]=Num2Bits(32);scalarBits[0].in<==lower;
    scalarBits[1]=Num2Bits(32);scalarBits[1].in<==upper;
    component nonempty=LessThan(32);nonempty.in[0]<==lower;nonempty.in[1]<==upper;nonempty.out===1;
    component rec[N+2];component opening[N+2];
    component afterLower[N];component beforeUpper[N];component chronological[N-1];
    for(var i=0;i<N+2;i++) {
        rec[i]=Record();opening[i]=Path(D);
        if(i<N) {
            for(var j=0;j<7;j++)rec[i].fields[j]<==records[i][j];
            opening[i].index<==startIndex+i;
            afterLower[i]=LessEqThan(32);afterLower[i].in[0]<==lower;afterLower[i].in[1]<==records[i][1];afterLower[i].out===1;
            beforeUpper[i]=LessThan(32);beforeUpper[i].in[0]<==records[i][1];beforeUpper[i].in[1]<==upper;beforeUpper[i].out===1;
            if(i>0) {
                chronological[i-1]=LessEqThan(32);chronological[i-1].in[0]<==records[i-1][1];chronological[i-1].in[1]<==records[i][1];chronological[i-1].out===1;
            }
        } else {
            for(var j=0;j<7;j++)rec[i].fields[j]<==boundary[i-N][j];
            if(i==N)opening[i].index<==startIndex-1;
            else opening[i].index<==startIndex+N;
        }
        opening[i].leaf<==rec[i].digest;
        for(var h=0;h<D;h++)opening[i].siblings[h]<==paths[i][h];
        opening[i].root===timeRoot;
    }
    component left=LessThan(32);left.in[0]<==boundary[0][1];left.in[1]<==lower;left.out===1;
    component right=LessEqThan(32);right.in[0]<==upper;right.in[1]<==boundary[1][1];right.out===1;
    component c=Commitment(N);c.salt<==salt;c.context[0]<==nonce;c.context[1]<==timeRoot;c.context[2]<==lower;c.context[3]<==upper;
    for(var i=0;i<N;i++)for(var j=0;j<7;j++)c.records[i][j]<==records[i][j];
    c.digest===commitment;
}

// Opens the SAME C_E as GammaQ. Its validity depends on independently verifying
// GammaQ and equality of the shared context, not on trusting C_E from the sender.
template GammaP(N) {
    signal input commitment;signal input nonce;signal input timeRoot;
    signal input lower;signal input upper;
    signal input evaluationTime;signal input deadline;signal input maxRisk;signal input decision;
    signal input records[N][7];signal input salt;
    component c=Commitment(N);c.salt<==salt;c.context[0]<==nonce;c.context[1]<==timeRoot;c.context[2]<==lower;c.context[3]<==upper;
    component bit[N][7];
    component life[N];component assessment[N];component risk[N];component from[N];component until[N];
    signal good[N][6];signal all[N+1];all[0]<==1;
    component time=LessEqThan(32);time.in[0]<==evaluationTime;time.in[1]<==deadline;time.out===1;
    component taskBits[3];taskBits[0]=Num2Bits(32);taskBits[0].in<==evaluationTime;
    taskBits[1]=Num2Bits(32);taskBits[1].in<==deadline;taskBits[2]=Num2Bits(32);taskBits[2].in<==maxRisk;
    for(var i=0;i<N;i++) {
        for(var j=0;j<7;j++) {bit[i][j]=Num2Bits(32);bit[i][j].in<==records[i][j];c.records[i][j]<==records[i][j];}
        life[i]=IsEqual();life[i].in[0]<==records[i][5];life[i].in[1]<==1;
        assessment[i]=IsEqual();assessment[i].in[0]<==records[i][6];assessment[i].in[1]<==1;
        risk[i]=LessEqThan(32);risk[i].in[0]<==records[i][4];risk[i].in[1]<==maxRisk;
        from[i]=LessEqThan(32);from[i].in[0]<==records[i][2];from[i].in[1]<==evaluationTime;
        until[i]=LessThan(32);until[i].in[0]<==deadline;until[i].in[1]<==records[i][3];
        good[i][0]<==1;good[i][1]<==life[i].out;
        good[i][2]<==good[i][1]*assessment[i].out;good[i][3]<==good[i][2]*risk[i].out;
        good[i][4]<==good[i][3]*from[i].out;good[i][5]<==good[i][4]*until[i].out;
        all[i+1]<==all[i]*good[i][5];
    }
    c.digest===commitment;decision===all[N];
}

// Both variants include identical binding overhead. A Fiat-Shamir product check
// binds the externally sorted candidate to the original committed multiset.
// This is a dedup kernel, NOT the registry/DAG closure circuit.
template Lambda(K, NAIVE) {
    signal input inputCommit;signal input orderedCommit;signal input nonce;signal input recordCount;
    signal input original[K];signal input values[K];
    component raw=Hash(K,205);component ordered=Hash(K,205);
    component boundRaw[K];component boundOrdered[K];
    for(var i=0;i<K;i++) {
        raw.in[i]<==original[i];ordered.in[i]<==values[i];
        boundRaw[i]=Num2Bits(32);boundRaw[i].in<==original[i];
        boundOrdered[i]=Num2Bits(32);boundOrdered[i].in<==values[i];
    }
    raw.out===inputCommit;ordered.out===orderedCommit;
    component challenge=Hash(3,206);challenge.in[0]<==inputCommit;challenge.in[1]<==orderedCommit;challenge.in[2]<==nonce;
    signal a[K+1];signal b[K+1];a[0]<==1;b[0]<==1;
    for(var i=0;i<K;i++) {
        a[i+1]<==a[i]*(challenge.out+original[i]);b[i+1]<==b[i]*(challenge.out+values[i]);
    }
    a[K]===b[K];
    signal fresh[K];
    if(NAIVE==1) {
        component eq[K][K];signal unseen[K][K+1];
        for(var i=0;i<K;i++) {
            unseen[i][0]<==1;
            for(var j=0;j<K;j++) {
                if(j<i) {
                    eq[i][j]=IsEqual();eq[i][j].in[0]<==values[i];eq[i][j].in[1]<==values[j];
                    unseen[i][j+1]<==unseen[i][j]*(1-eq[i][j].out);
                } else unseen[i][j+1]<==unseen[i][j];
            }
            fresh[i]<==unseen[i][K];
        }
    } else {
        component le[K-1];component eq[K-1];fresh[0]<==1;
        for(var i=1;i<K;i++) {
            le[i-1]=LessEqThan(32);le[i-1].in[0]<==values[i-1];le[i-1].in[1]<==values[i];le[i-1].out===1;
            eq[i-1]=IsEqual();eq[i-1].in[0]<==values[i-1];eq[i-1].in[1]<==values[i];
            fresh[i]<==1-eq[i-1].out;
        }
    }
    var count=0;for(var i=0;i<K;i++)count+=fresh[i];recordCount===count;
}
