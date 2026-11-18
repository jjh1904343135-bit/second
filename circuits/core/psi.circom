pragma circom 2.1.6;
include "common.circom";

// state = profile, source, sequence, logRoot[2], directoryRoot[2].
// The imported R1CS has EXACTLY seven outputs and seven public old-state inputs.
template PsiStep(R,PROFILE,EMPTY_SLOT0,EMPTY_SLOT1) {
    var H=0;var width=R;while(width>1){H++;width=width\2;}
    signal input state[7];signal output next[7];
    signal input op;signal input oldCount;
    signal input oldRecord[35];signal input newRecord[35];
    signal input slotSiblings[H][2];signal input directorySiblings[48][2];signal input logSiblings[32][2];
    component opEq[3];for(var i=0;i<3;i++){opEq[i]=IsEqual();opEq[i].in[0]<==op;opEq[i].in[1]<==i+1;}
    opEq[0].out+opEq[1].out+opEq[2].out===1;
    state[0]===PROFILE;
    component sourceBits=Num2Bits(32);sourceBits.in<==state[1];
    component sourceNonzero=IsZero();sourceNonzero.in<==state[1];sourceNonzero.out===0;
    component seqOld=Num2Bits(32);seqOld.in<==state[2];
    component seqNew=Num2Bits(32);seqNew.in<==state[2]+1;
    component before=CoreRecord();component after=CoreRecord();
    before.enabled<==1-opEq[0].out;after.enabled<==1;
    for(var i=0;i<35;i++){before.words[i]<==oldRecord[i];after.words[i]<==newRecord[i];}
    newRecord[1]===state[1];
    opEq[0].out*(newRecord[2]-state[2]-1)===0;
    opEq[0].out*(newRecord[3]-1)===0;
    opEq[0].out*(newRecord[6]-oldCount)===0;
    newRecord[15]===1+opEq[2].out;
    (1-opEq[0].out)*(oldRecord[15]-1)===0;
    (1-opEq[0].out)*(newRecord[3]-oldRecord[3]-1)===0;
    var immutable[7]=[1,2,4,5,6,7,8];
    for(var i=0;i<7;i++)(1-opEq[0].out)*(newRecord[immutable[i]]-oldRecord[immutable[i]])===0;
    component updated=LessEqThan(64);updated.in[0]<==oldRecord[9]*4294967296+oldRecord[10];updated.in[1]<==newRecord[9]*4294967296+newRecord[10];updated.out===1;
    component countBounds=Num2Bits(8);countBounds.in<==oldCount;
    component countLimit=LessEqThan(8);countLimit.in[0]<==oldCount+opEq[0].out;countLimit.in[1]<==R;countLimit.out===1;
    component exists=LessThan(8);exists.in[0]<==newRecord[6];exists.in[1]<==oldCount;
    (1-opEq[0].out)*(1-exists.out)===0;
    component countZero=IsZero();countZero.in<==oldCount;
    component emptySlot=CoreHash(0,2,0);component beforeSlot=CoreHash(2,3,0);component afterSlot=CoreHash(2,3,0);
    component oldSlots=CorePath(H,4);component newSlots=CorePath(H,4);
    for(var l=0;l<2;l++){beforeSlot.words[l]<==before.digest[l];afterSlot.words[l]<==after.digest[l];}
    for(var l=0;l<2;l++) {
        oldSlots.leaf[l]<==beforeSlot.digest[l]+opEq[0].out*(emptySlot.digest[l]-beforeSlot.digest[l]);
        newSlots.leaf[l]<==afterSlot.digest[l];
        for(var h=0;h<H;h++){oldSlots.siblings[h][l]<==slotSiblings[h][l];newSlots.siblings[h][l]<==slotSiblings[h][l];}
    }
    oldSlots.index<==newRecord[6];newSlots.index<==newRecord[6];
    countZero.out*(oldSlots.root[0]-EMPTY_SLOT0)===0;countZero.out*(oldSlots.root[1]-EMPTY_SLOT1)===0;
    component oldBucket=CoreHash(5,5,0);component newBucket=CoreHash(5,5,0);component absent=CoreHash(0,6,0);
    oldBucket.words[0]<==newRecord[4];newBucket.words[0]<==newRecord[4];
    oldBucket.words[1]<==newRecord[5];newBucket.words[1]<==newRecord[5];
    oldBucket.words[2]<==oldCount;newBucket.words[2]<==oldCount+opEq[0].out;
    for(var l=0;l<2;l++){oldBucket.words[3+l]<==oldSlots.root[l];newBucket.words[3+l]<==newSlots.root[l];}
    component oldDir=CorePath(48,7);component newDir=CorePath(48,7);
    oldDir.index<==newRecord[4]*65536+newRecord[5];newDir.index<==newRecord[4]*65536+newRecord[5];
    for(var l=0;l<2;l++) {
        oldDir.leaf[l]<==oldBucket.digest[l]+countZero.out*(absent.digest[l]-oldBucket.digest[l]);
        newDir.leaf[l]<==newBucket.digest[l];
        for(var h=0;h<48;h++){oldDir.siblings[h][l]<==directorySiblings[h][l];newDir.siblings[h][l]<==directorySiblings[h][l];}
    }
    for(var l=0;l<2;l++)oldDir.root[l]===state[5+l];
    component eventHash=CoreHash(6,8,0);
    eventHash.words[0]<==op;eventHash.words[1]<==oldRecord[3];
    for(var l=0;l<2;l++){eventHash.words[2+l]<==(1-opEq[0].out)*before.digest[l];eventHash.words[4+l]<==after.digest[l];}
    component logLeaf=CoreHash(3,9,0);component logEmpty=CoreHash(0,10,0);
    logLeaf.words[0]<==state[2]+1;for(var l=0;l<2;l++)logLeaf.words[l+1]<==eventHash.digest[l];
    component oldLog=CorePath(32,11);component newLog=CorePath(32,11);
    oldLog.index<==state[2];newLog.index<==state[2];
    for(var l=0;l<2;l++) {
        oldLog.leaf[l]<==logEmpty.digest[l];newLog.leaf[l]<==logLeaf.digest[l];
        for(var h=0;h<32;h++){oldLog.siblings[h][l]<==logSiblings[h][l];newLog.siblings[h][l]<==logSiblings[h][l];}
    }
    for(var l=0;l<2;l++){oldLog.root[l]===state[3+l];next[3+l]<==newLog.root[l];next[5+l]<==newDir.root[l];}
    next[0]<==state[0];next[1]<==state[1];next[2]<==state[2]+1;
}
