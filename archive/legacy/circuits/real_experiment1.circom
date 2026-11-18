pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mimcsponge.circom";

// Experimental bounded REAL profile, distinct from the final Nova profile:
// 3 sources, 4 events per source, 8 registered nodes, 4 parents per node.
// MiMC-sponge([profile domain, kind, fixed word count, fixed u32 words]), key=0, 220 rounds.
// Two field outputs are native BN254 scalars, NOT SHA256 limbs.
template DigestWords(N, kind) {
    signal input words[N];
    signal output digest[2];
    component bits[N];
    component hash = MiMCSponge(N+3,220,2);
    hash.k <== 0;
    hash.ins[0]<==1380141125;hash.ins[1]<==kind;hash.ins[2]<==N;
    for(var i=0;i<N;i++) {
        bits[i] = Num2Bits(32); bits[i].in <== words[i];
        hash.ins[i+3]<==words[i];
    }
    digest[0]<==hash.outs[0];digest[1]<==hash.outs[1];
}
template And(N) {
    signal input in[N]; signal output out; signal p[N+1]; p[0]<==1;
    for(var i=0;i<N;i++) p[i+1]<==p[i]*in[i];
    out<==p[N];
}
template Or(N) {
    signal input in[N]; signal output out; signal p[N+1]; p[0]<==1;
    for(var i=0;i<N;i++) p[i+1]<==p[i]*(1-in[i]);
    out<==1-p[N];
}

template RealExperiment1() {
    // Public inputs are reconstructed by the receiving Agent, never trusted as A's labels.
    signal input logRoot[3][2];signal input timeRoot[3][2];signal input lifeRoot[3][2]; signal input registryRoot[2];
    signal input nonce[8]; signal input handoffCommit[8];
    signal input mode; signal input evaluationTime; signal input auditTime; signal input deadline;
    signal input createdFrom; signal input createdUntil; signal input maxRisk;
    signal input minRecords; signal input minIssuers; signal input groups[3];
    signal input objectId; signal input evidenceType;
    signal input requiredSources[3];signal input requireEach;
    signal input decision; signal input reason;
    // event: op,id,version,created,updated,from,until,life,assessment,risk,purpose,object,type,slot,8 salt words
    signal input events[3][4][22]; signal input eventCount[3];
    // complete time order: record ID (zero padded); returned bit for each time position
    signal input timeOrder[3][4]; signal input returned[3][4];
    signal input leftBoundary[3];signal input rightBoundary[3];
    // node: active,kind,op,source,id,version,parent[4],content[8],salt[8]
    signal input nodes[8][26];

    component modeBit=Num2Bits(1); modeBit.in<==mode;
    // Tight neighboring positions around the claimed interval: 0 is the left sentinel.
    for(var src=0;src<3;src++)leftBoundary[src]+returned[src][0]+returned[src][1]+returned[src][2]+returned[src][3]+1===rightBoundary[src];
    requireEach*(requireEach-1)===0;
    for(var s=0;s<3;s++)requiredSources[s]*(requiredSources[s]-1)===0;
    component taskBounds[11];
    signal taskWords[11];
    taskWords[0]<==evaluationTime; taskWords[1]<==auditTime; taskWords[2]<==deadline;
    taskWords[3]<==createdFrom; taskWords[4]<==createdUntil; taskWords[5]<==maxRisk;
    taskWords[6]<==minRecords; taskWords[7]<==minIssuers; taskWords[8]<==groups[0]; taskWords[9]<==groups[1]; taskWords[10]<==groups[2];
    for(var i=0;i<11;i++){taskBounds[i]=Num2Bits(32);taskBounds[i].in<==taskWords[i];}
    signal start; signal end;
    start<==evaluationTime+mode*(auditTime-evaluationTime);
    end<==deadline+mode*(auditTime-deadline);
    component seqActive[3][4];
    component sourceHash[3];
    component matchId[3][4][4];
    component eligibleTime[3][4];
    signal active[3][4]; signal eligible[3][4];
    component candidate[3][4][4];
    component latest[3][4][4];
    signal chosen[3][4][4];
    signal current[3][4][14];
    signal exists[3][4];
    component latestNow[3][4][4];signal nowPick[3][4][4];signal existsNow[3][4];
    signal nowFieldTerms[3][4][6][4];signal nowFields[3][4][6];
    for(var s=0;s<3;s++) {
        sourceHash[s]=DigestWords(90,1);
        sourceHash[s].words[0]<==s+1; sourceHash[s].words[1]<==eventCount[s];
        for(var t=0;t<4;t++) {
            seqActive[s][t]=LessThan(32);seqActive[s][t].in[0]<==t;seqActive[s][t].in[1]<==eventCount[s];
            active[s][t]<==seqActive[s][t].out;
            for(var f=0;f<22;f++) {
                sourceHash[s].words[2+t*22+f]<==events[s][t][f];
                (1-active[s][t])*events[s][t][f]===0;
            }
            eligibleTime[s][t]=LessEqThan(32);eligibleTime[s][t].in[0]<==events[s][t][4];eligibleTime[s][t].in[1]<==auditTime;
            eligible[s][t]<==1-mode*(1-eligibleTime[s][t].out);
            for(var r=0;r<4;r++) {
                matchId[s][r][t]=IsEqual();matchId[s][r][t].in[0]<==events[s][t][1];matchId[s][r][t].in[1]<==r+1;
                candidate[s][r][t]=And(3);candidate[s][r][t].in[0]<==active[s][t];candidate[s][r][t].in[1]<==eligible[s][t];candidate[s][r][t].in[2]<==matchId[s][r][t].out;
            }
        }
        for(var limb=0;limb<2;limb++) sourceHash[s].digest[limb]===logRoot[s][limb];
        for(var r=0;r<4;r++) {
            for(var t=0;t<4;t++) {
                latestNow[s][r][t]=And(5);latestNow[s][r][t].in[0]<==active[s][t];
                for(var u=0;u<4;u++){
                    if(u>t)latestNow[s][r][t].in[u+1]<==1-matchId[s][r][u].out;
                    else latestNow[s][r][t].in[u+1]<==1;
                }
                // A second identity gate is required independently of the historical selector.
                nowPick[s][r][t]<==latestNow[s][r][t].out*matchId[s][r][t].out;
                latest[s][r][t]=And(5);
                latest[s][r][t].in[0]<==candidate[s][r][t].out;
                for(var u=0;u<4;u++) {
                    if(u>t) latest[s][r][t].in[u+1]<==1-candidate[s][r][u].out;
                    else latest[s][r][t].in[u+1]<==1;
                }
                chosen[s][r][t]<==latest[s][r][t].out;
            }
            exists[s][r]<==chosen[s][r][0]+chosen[s][r][1]+chosen[s][r][2]+chosen[s][r][3];
            existsNow[s][r]<==nowPick[s][r][0]+nowPick[s][r][1]+nowPick[s][r][2]+nowPick[s][r][3];
            for(var f=0;f<14;f++) {
                // Split products into separate constrained wires.
                var sum=0;
                for(var t=0;t<4;t++) sum += 0;
            }
        }
    }
    signal selectedField[3][4][14][4];
    for(var s=0;s<3;s++)for(var r=0;r<4;r++)for(var f=0;f<14;f++){
        for(var t=0;t<4;t++)selectedField[s][r][f][t]<==chosen[s][r][t]*events[s][t][f];
        current[s][r][f]<==selectedField[s][r][f][0]+selectedField[s][r][f][1]+selectedField[s][r][f][2]+selectedField[s][r][f][3];
    }
    var nowIndices[6]=[3,2,7,4,5,6];
    for(var src=0;src<3;src++)for(var rec=0;rec<4;rec++)for(var f=0;f<6;f++){
        for(var t=0;t<4;t++)nowFieldTerms[src][rec][f][t]<==nowPick[src][rec][t]*events[src][t][nowIndices[f]];
        nowFields[src][rec][f]<==nowFieldTerms[src][rec][f][0]+nowFieldTerms[src][rec][f][1]+nowFieldTerms[src][rec][f][2]+nowFieldTerms[src][rec][f][3];
    }

    // Complete authenticated index permutation + exact query selection.
    component orderMatch[3][4][4]; component orderAllowed[3][4];
    signal orderPick[3][4][4]; signal orderedCreated[3][4]; signal orderUsed[3][4];
    signal orderProduct[3][4][4];
    component timeHash[3];component lifeHash[3];
    component timeLt[3][4];component sameTime[3][4];component idLt[3][4];
    signal tieOrder[3][4];signal ordered[3][4];
    signal beforeLower[3][4];signal beforeUpper[3][4];
    component lower[3][4];component upper[3][4]; component rangeHit[3][4];
    component objectEq[3][4];component typeEq[3][4];component qHit[3][4];
    component good[3][4]; component lifeEq[3][4];component passEq[3][4];
    component riskLE[3][4];component validFromLE[3][4];component endLT[3][4];
    component purposeBits[3][4];
    signal queryHit[3][4];signal recordGood[3][4];
    for(var s=0;s<3;s++) {
        timeHash[s]=DigestWords(14,3);lifeHash[s]=DigestWords(22,4);
        timeHash[s].words[0]<==s+1;lifeHash[s].words[0]<==s+1;
        timeHash[s].words[1]<==existsNow[s][0]+existsNow[s][1]+existsNow[s][2]+existsNow[s][3];lifeHash[s].words[1]<==existsNow[s][0]+existsNow[s][1]+existsNow[s][2]+existsNow[s][3];
        for(var rec=0;rec<4;rec++)for(var f=0;f<5;f++)lifeHash[s].words[2+rec*5+f]<==nowFields[s][rec][f+1];
        for(var p=0;p<4;p++){
            orderAllowed[s][p]=Or(4);
            for(var r=0;r<4;r++){
                orderMatch[s][p][r]=IsEqual();orderMatch[s][p][r].in[0]<==timeOrder[s][p];orderMatch[s][p][r].in[1]<==r+1;
                orderPick[s][p][r]<==orderMatch[s][p][r].out*existsNow[s][r];
                orderAllowed[s][p].in[r]<==orderPick[s][p][r];
                orderProduct[s][p][r]<==orderPick[s][p][r]*nowFields[s][r][0];
            }
            orderUsed[s][p]<==orderAllowed[s][p].out;
            (1-orderUsed[s][p])*timeOrder[s][p]===0;
            orderedCreated[s][p]<==orderProduct[s][p][0]+orderProduct[s][p][1]+orderProduct[s][p][2]+orderProduct[s][p][3];
            timeHash[s].words[2+p*3]<==timeOrder[s][p];timeHash[s].words[3+p*3]<==orderedCreated[s][p];timeHash[s].words[4+p*3]<==orderUsed[s][p];
            if(p>0){
                orderUsed[s][p]*(1-orderUsed[s][p-1])===0;
                timeLt[s][p]=LessThan(32);timeLt[s][p].in[0]<==orderedCreated[s][p-1];timeLt[s][p].in[1]<==orderedCreated[s][p];
                sameTime[s][p]=IsEqual();sameTime[s][p].in[0]<==orderedCreated[s][p-1];sameTime[s][p].in[1]<==orderedCreated[s][p];
                idLt[s][p]=LessThan(32);idLt[s][p].in[0]<==timeOrder[s][p-1];idLt[s][p].in[1]<==timeOrder[s][p];
                tieOrder[s][p]<==sameTime[s][p].out*idLt[s][p].out;ordered[s][p]<==timeLt[s][p].out+tieOrder[s][p];
                orderUsed[s][p]*(1-ordered[s][p])===0;
            }
            lower[s][p]=LessEqThan(32);lower[s][p].in[0]<==createdFrom;lower[s][p].in[1]<==orderedCreated[s][p];
            upper[s][p]=LessThan(32);upper[s][p].in[0]<==orderedCreated[s][p];upper[s][p].in[1]<==createdUntil;
            rangeHit[s][p]=And(3);rangeHit[s][p].in[0]<==orderUsed[s][p];rangeHit[s][p].in[1]<==lower[s][p].out;rangeHit[s][p].in[2]<==upper[s][p].out;
            beforeLower[s][p]<==orderUsed[s][p]*(1-lower[s][p].out);beforeUpper[s][p]<==orderUsed[s][p]*upper[s][p].out;
            // This exact-selection equality closes both neighbor boundaries, including late arrivals.
            returned[s][p]===rangeHit[s][p].out;
        }
        leftBoundary[s]===beforeLower[s][0]+beforeLower[s][1]+beforeLower[s][2]+beforeLower[s][3];
        rightBoundary[s]===beforeUpper[s][0]+beforeUpper[s][1]+beforeUpper[s][2]+beforeUpper[s][3]+1;
        for(var limb=0;limb<2;limb++){timeHash[s].digest[limb]===timeRoot[s][limb];lifeHash[s].digest[limb]===lifeRoot[s][limb];}
        for(var r=0;r<4;r++) {
            orderPick[s][0][r]+orderPick[s][1][r]+orderPick[s][2][r]+orderPick[s][3][r]===existsNow[s][r];
            objectEq[s][r]=IsEqual();objectEq[s][r].in[0]<==current[s][r][11];objectEq[s][r].in[1]<==objectId;
            typeEq[s][r]=IsEqual();typeEq[s][r].in[0]<==current[s][r][12];typeEq[s][r].in[1]<==evidenceType;
            qHit[s][r]=And(6);qHit[s][r].in[0]<==exists[s][r];qHit[s][r].in[1]<==objectEq[s][r].out;qHit[s][r].in[2]<==typeEq[s][r].out;qHit[s][r].in[5]<==requiredSources[s];
            // Reuse comparisons against the actual current record, independent of index position.
        }
    }
    component qLower[3][4];component qUpper[3][4];
    for(var s=0;s<3;s++)for(var r=0;r<4;r++) {
        qLower[s][r]=LessEqThan(32);qLower[s][r].in[0]<==createdFrom;qLower[s][r].in[1]<==current[s][r][3];
        qUpper[s][r]=LessThan(32);qUpper[s][r].in[0]<==current[s][r][3];qUpper[s][r].in[1]<==createdUntil;
        qHit[s][r].in[3]<==qLower[s][r].out;qHit[s][r].in[4]<==qUpper[s][r].out;
        queryHit[s][r]<==qHit[s][r].out;
        lifeEq[s][r]=IsEqual();lifeEq[s][r].in[0]<==current[s][r][7];lifeEq[s][r].in[1]<==1;
        passEq[s][r]=IsEqual();passEq[s][r].in[0]<==current[s][r][8];passEq[s][r].in[1]<==1;
        riskLE[s][r]=LessEqThan(32);riskLE[s][r].in[0]<==current[s][r][9];riskLE[s][r].in[1]<==maxRisk;
        validFromLE[s][r]=LessEqThan(32);validFromLE[s][r].in[0]<==current[s][r][5];validFromLE[s][r].in[1]<==start;
        endLT[s][r]=LessThan(32);endLT[s][r].in[0]<==end;endLT[s][r].in[1]<==current[s][r][6];
        purposeBits[s][r]=Num2Bits(32);purposeBits[s][r].in<==current[s][r][10];
        good[s][r]=And(6);good[s][r].in[0]<==lifeEq[s][r].out;good[s][r].in[1]<==passEq[s][r].out;good[s][r].in[2]<==riskLE[s][r].out;good[s][r].in[3]<==validFromLE[s][r].out;good[s][r].in[4]<==endLT[s][r].out;good[s][r].in[5]<==purposeBits[s][r].out[0];
        recordGood[s][r]<==1-queryHit[s][r]*(1-good[s][r].out);
    }

    // Entire fixed-capacity authenticated registry is private; exact parents are committed.
    component graphHash=DigestWords(224,2);
    for(var n=0;n<8;n++)for(var f=0;f<26;f++)graphHash.words[n*26+f]<==nodes[n][f];
    for(var w=0;w<8;w++){graphHash.words[208+w]<==nonce[w];graphHash.words[216+w]<==handoffCommit[w];}
    graphHash.digest[0]===registryRoot[0];graphHash.digest[1]===registryRoot[1];
    signal nCount;
    nCount<==nodes[0][0]+nodes[1][0]+nodes[2][0]+nodes[3][0]+nodes[4][0]+nodes[5][0]+nodes[6][0]+nodes[7][0];
    component isFinal[8];component isRoot[8];
    component parentZero[8][4];component parentOrder[8][4];
    component hasParent[8];signal needsParent[8];component isHandoff[8];
    signal rootMatchesCount[8];
    component parentEq[8][4][8];signal adjacency[8][8];
    component adjacencyOr[8][8];component rootKeyEq[8][12][3];component rootMatch[8][12];
    component parentRoots[8][12];signal inheritedRoot[8][12][8];signal rootBits[8][12];
    signal finalBitsTerms[8][12];signal finalBits[12];
    component reachable[8];signal reach[8];signal reachTerms[8][8];
    for(var n=0;n<8;n++) {
        nodes[n][0]*(nodes[n][0]-1)===0;
        if(n>0)nodes[n][0]*(1-nodes[n-1][0])===0;
        isFinal[n]=IsEqual();isFinal[n].in[0]<==n+1;isFinal[n].in[1]<==nCount;
        isRoot[n]=IsEqual();isRoot[n].in[0]<==nodes[n][1];isRoot[n].in[1]<==1;
        nodes[n][1]===2*nodes[n][0]-isRoot[n].out;
        isRoot[n].out*(nodes[n][2]-1)===0;
        isHandoff[n]=IsEqual();isHandoff[n].in[0]<==nodes[n][2];isHandoff[n].in[1]<==6;
        isFinal[n].out*(nodes[n][2]-6)===0;
        for(var w=0;w<8;w++)isFinal[n].out*(nodes[n][10+w]-handoffCommit[w])===0;
        for(var f=1;f<26;f++)(1-nodes[n][0])*nodes[n][f]===0;
        for(var p=0;p<4;p++) {
            parentZero[n][p]=IsZero();parentZero[n][p].in<==nodes[n][6+p];
            isRoot[n].out*nodes[n][6+p]===0;
            for(var k=0;k<8;k++) {
                parentEq[n][p][k]=IsEqual();parentEq[n][p][k].in[0]<==nodes[n][6+p];parentEq[n][p][k].in[1]<==k+1;
                if(k>=n) parentEq[n][p][k].out===0;
                else parentEq[n][p][k].out*(1-nodes[k][0])===0;
            }
            parentZero[n][p].out+parentEq[n][p][0].out+parentEq[n][p][1].out+parentEq[n][p][2].out+parentEq[n][p][3].out+parentEq[n][p][4].out+parentEq[n][p][5].out+parentEq[n][p][6].out+parentEq[n][p][7].out===1;
            if(p>0){
                parentZero[n][p-1].out*(1-parentZero[n][p].out)===0;
                parentOrder[n][p]=LessThan(32);parentOrder[n][p].in[0]<==nodes[n][5+p];parentOrder[n][p].in[1]<==nodes[n][6+p];
                (1-parentZero[n][p].out)*(1-parentOrder[n][p].out)===0;
            }
        }
        for(var k=0;k<8;k++){
            adjacencyOr[n][k]=Or(4);for(var p=0;p<4;p++)adjacencyOr[n][k].in[p]<==parentEq[n][p][k].out;
            adjacency[n][k]<==adjacencyOr[n][k].out;
        }
        hasParent[n]=Or(8);for(var k=0;k<8;k++)hasParent[n].in[k]<==adjacency[n][k];
        needsParent[n]<==(nodes[n][0]-isRoot[n].out)*(1-isHandoff[n].out);
        needsParent[n]*(1-hasParent[n].out)===0;
        for(var e=0;e<12;e++) {
            var s=e\4;var t=e%4;
            rootKeyEq[n][e][0]=IsEqual();rootKeyEq[n][e][0].in[0]<==nodes[n][3];rootKeyEq[n][e][0].in[1]<==s+1;
            rootKeyEq[n][e][1]=IsEqual();rootKeyEq[n][e][1].in[0]<==nodes[n][4];rootKeyEq[n][e][1].in[1]<==events[s][t][1];
            rootKeyEq[n][e][2]=IsEqual();rootKeyEq[n][e][2].in[0]<==nodes[n][5];rootKeyEq[n][e][2].in[1]<==events[s][t][2];
            rootMatch[n][e]=And(5);rootMatch[n][e].in[0]<==isRoot[n].out;rootMatch[n][e].in[1]<==active[s][t];for(var j=0;j<3;j++)rootMatch[n][e].in[j+2]<==rootKeyEq[n][e][j].out;
            parentRoots[n][e]=Or(8);
            for(var k=0;k<8;k++){
                if(k<n) inheritedRoot[n][e][k]<==adjacency[n][k]*rootBits[k][e];
                else inheritedRoot[n][e][k]<==0;
                parentRoots[n][e].in[k]<==inheritedRoot[n][e][k];
            }
            rootBits[n][e]<==rootMatch[n][e].out+(1-isRoot[n].out)*parentRoots[n][e].out;
            finalBitsTerms[n][e]<==isFinal[n].out*rootBits[n][e];
        }
        rootMatchesCount[n]<==rootMatch[n][0].out+rootMatch[n][1].out+rootMatch[n][2].out+rootMatch[n][3].out+rootMatch[n][4].out+rootMatch[n][5].out+rootMatch[n][6].out+rootMatch[n][7].out+rootMatch[n][8].out+rootMatch[n][9].out+rootMatch[n][10].out+rootMatch[n][11].out;
        rootMatchesCount[n]===isRoot[n].out;
    }
    for(var e=0;e<12;e++)finalBits[e]<==finalBitsTerms[0][e]+finalBitsTerms[1][e]+finalBitsTerms[2][e]+finalBitsTerms[3][e]+finalBitsTerms[4][e]+finalBitsTerms[5][e]+finalBitsTerms[6][e]+finalBitsTerms[7][e];
    for(var rev=0;rev<8;rev++) {
        var n=7-rev;reachable[n]=Or(9);reachable[n].in[0]<==isFinal[n].out;
        for(var k=0;k<8;k++){
            if(k>n) reachTerms[n][k]<==reach[k]*adjacency[k][n];else reachTerms[n][k]<==0;
            reachable[n].in[k+1]<==reachTerms[n][k];
        }
        reach[n]<==reachable[n].out;reach[n]===nodes[n][0];
    }

    component rootEligible[12];component rootSelectedMatch[12][4];component versionEq[12][4];
    component identityEq[12][4]; signal eligibility[12][4];component eligibleOr[12];
    signal qualified[12];signal supportGood[12];
    component recordCounts[3][4];component sourceUsed[3];
    component groupEq[3][3];component priorGroup[3];signal previousGroupTerms[3][3];signal uniqueGroup[3];
    for(var e=0;e<12;e++) {
        var s=e\4;var t=e%4;eligibleOr[e]=Or(4);
        for(var r=0;r<4;r++){
            versionEq[e][r]=IsEqual();versionEq[e][r].in[0]<==events[s][t][2];versionEq[e][r].in[1]<==current[s][r][2];
            identityEq[e][r]=IsEqual();identityEq[e][r].in[0]<==events[s][t][1];identityEq[e][r].in[1]<==r+1;
            rootSelectedMatch[e][r]=And(4);rootSelectedMatch[e][r].in[0]<==identityEq[e][r].out;rootSelectedMatch[e][r].in[1]<==versionEq[e][r].out;rootSelectedMatch[e][r].in[2]<==queryHit[s][r];rootSelectedMatch[e][r].in[3]<==good[s][r].out;
            eligibility[e][r]<==rootSelectedMatch[e][r].out;eligibleOr[e].in[r]<==eligibility[e][r];
        }
        qualified[e]<==finalBits[e]*eligibleOr[e].out;
        supportGood[e]<==1-finalBits[e]*(1-eligibleOr[e].out);
    }
    signal recordCount;signal issuerCount;
    component actualRecord[3][4];signal countedRecord[3][4][4];
    for(var s=0;s<3;s++) {
        sourceUsed[s]=Or(4);
        for(var r=0;r<4;r++){
            actualRecord[s][r]=Or(4);
            for(var t=0;t<4;t++){countedRecord[s][r][t]<==qualified[s*4+t]*matchId[s][r][t].out;actualRecord[s][r].in[t]<==countedRecord[s][r][t];}
            sourceUsed[s].in[r]<==actualRecord[s][r].out;
        }
        priorGroup[s]=Or(3);
        for(var k=0;k<3;k++){
            groupEq[s][k]=IsEqual();groupEq[s][k].in[0]<==groups[s];groupEq[s][k].in[1]<==groups[k];
            if(k<s)previousGroupTerms[s][k]<==sourceUsed[k].out*groupEq[s][k].out;else previousGroupTerms[s][k]<==0;
            priorGroup[s].in[k]<==previousGroupTerms[s][k];
        }
        uniqueGroup[s]<==sourceUsed[s].out*(1-priorGroup[s].out);
    }
    recordCount<==actualRecord[0][0].out+actualRecord[0][1].out+actualRecord[0][2].out+actualRecord[0][3].out+actualRecord[1][0].out+actualRecord[1][1].out+actualRecord[1][2].out+actualRecord[1][3].out+actualRecord[2][0].out+actualRecord[2][1].out+actualRecord[2][2].out+actualRecord[2][3].out;
    issuerCount<==uniqueGroup[0]+uniqueGroup[1]+uniqueGroup[2];
    component recordsEnough=LessEqThan(32);recordsEnough.in[0]<==minRecords;recordsEnough.in[1]<==recordCount;
    component issuersEnough=LessEqThan(32);issuersEnough.in[0]<==minIssuers;issuersEnough.in[1]<==issuerCount;
    component p=And(15);component support=And(12);component s=And(3);
    component sourceHasQ[3];signal requiredCoverage[3];signal coverageGood[3];
    for(var src=0;src<3;src++){
        sourceHasQ[src]=Or(4);for(var r=0;r<4;r++)sourceHasQ[src].in[r]<==queryHit[src][r];
        requiredCoverage[src]<==requiredSources[src]*requireEach;
        coverageGood[src]<==1-requiredCoverage[src]*(1-sourceHasQ[src].out);
        p.in[12+src]<==coverageGood[src];
    }
    for(var i=0;i<12;i++){p.in[i]<==recordGood[i\4][i%4];support.in[i]<==supportGood[i];}
    s.in[0]<==support.out;s.in[1]<==recordsEnough.out;s.in[2]<==issuersEnough.out;
    decision===p.out*s.out;
    reason===1-p.out+2*(p.out-decision);
}
component main {public [logRoot,timeRoot,lifeRoot,registryRoot,nonce,handoffCommit,mode,evaluationTime,auditTime,deadline,createdFrom,createdUntil,maxRisk,minRecords,minIssuers,groups,objectId,evidenceType,requiredSources,requireEach,decision,reason]}=RealExperiment1();
