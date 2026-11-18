pragma circom 2.1.6;
include "common.circom";

// MODE: 0 FULL, 1 submitted-subset query, 2 no current-version/WindowValid,
// 3 self-reported lineage. Binding ablations use FULL plus a lab-only receiver.
template CoreJoint(S,R,G,PROFILE,MODE) {
    signal input profileId;signal input sourceIds[S];signal input logLengths[S];
    signal input logRoots[S][2];signal input stateRoots[S][2];
    signal input registryRoot[2];signal input registryLength;
    signal input handoffNode[2];signal input handoffCommit[2];signal input taskDigest[8];
    signal input objectId;signal input evidenceType;
    signal input lower[2];signal input upper[2];signal input evaluation[2];signal input deadline[2];
    signal input maxRisk;signal input purposeBit;signal input minGroups;signal input requireEach;signal input sourceGroups[S];
    signal input qCommit[2];signal input lCommit[2];signal input decision;signal input reason;
    signal input records[S][R][35];signal input counts[S];signal input directoryPaths[S][48][2];
    signal input selected[S][R];signal input qSalt[8];signal input lSalt[8];
    signal input nodes[G][18];signal input parents[G][4];signal input parentSalts[G][8];
    signal input registryPaths[G][32][2];signal input rootRecords[G][35];
    signal input eventMeta[G][4];signal input eventSeq[G];signal input logPaths[G][32][2];
    signal input sortedRoots[G][6];signal input claimedGroups[S];
    profileId===PROFILE;requireEach*(requireEach-1)===0;
    component taskBits[25+3*S];signal taskWords[25+3*S];
    taskWords[0]<==objectId;taskWords[1]<==evidenceType;
    for(var i=0;i<2;i++){taskWords[2+i]<==lower[i];taskWords[4+i]<==upper[i];taskWords[6+i]<==evaluation[i];taskWords[8+i]<==deadline[i];}
    taskWords[10]<==maxRisk;taskWords[11]<==purposeBit;taskWords[12]<==minGroups;taskWords[13]<==registryLength;
    for(var i=0;i<8;i++)taskWords[14+i]<==taskDigest[i];
    taskWords[22]<==profileId;taskWords[23]<==decision;taskWords[24]<==reason;
    for(var s=0;s<S;s++){taskWords[25+s*3]<==sourceIds[s];taskWords[26+s*3]<==logLengths[s];taskWords[27+s*3]<==sourceGroups[s];}
    for(var i=0;i<25+3*S;i++){taskBits[i]=Num2Bits(32);taskBits[i].in<==taskWords[i];}
    component purposeBound=Num2Bits(5);purposeBound.in<==purposeBit;
    component typeBound=Num2Bits(16);typeBound.in<==evidenceType;
    component interval=LessThan(64);interval.in[0]<==lower[0]*4294967296+lower[1];interval.in[1]<==upper[0]*4294967296+upper[1];interval.out===1;
    component time=LessEqThan(64);time.in[0]<==evaluation[0]*4294967296+evaluation[1];time.in[1]<==deadline[0]*4294967296+deadline[1];time.out===1;
    component sourceOrder[S];component nonzero[S];
    for(var s=0;s<S;s++) {
        nonzero[s]=IsZero();nonzero[s].in<==sourceIds[s];nonzero[s].out===0;
        if(s>0){sourceOrder[s]=LessThan(32);sourceOrder[s].in[0]<==sourceIds[s-1];sourceOrder[s].in[1]<==sourceIds[s];sourceOrder[s].out===1;}
    }
    component rec[S][R];component exists[S][R];component slotHash[S][R];
    component slotTree[S];component bucket[S];component directory[S];component countBound[S];component countBits[S];
    component emptySlot=CoreHash(0,2,0);component emptyDir=CoreHash(0,6,0);component countZero[S];
    component lowerOK[S][R];component upperOK[S][R];component hitGate[S][R];
    component life[S][R];component assessment[S][R];component risk[S][R];component fromOK[S][R];component untilOK[S][R];
    component purposeBits[S][R];component purposeEq[S][R][32];signal purposeTerms[S][R][32];signal purposeOK[S][R];
    component validity[S][R];component businessOK[S][R];signal recordOK[S][R];signal effectiveValid[S][R];
    component coverage[S];signal sourceOK[S];component allCoverage=CoreAnd(S);component allRecords=CoreAnd(S*R);
    component qHash=CoreHash(16+3*S*R,18,0);component qSaltBits[8];component lSaltBits[8];
    for(var i=0;i<8;i++) {
        qSaltBits[i]=Num2Bits(32);qSaltBits[i].in<==qSalt[i];lSaltBits[i]=Num2Bits(32);lSaltBits[i].in<==lSalt[i];
        qHash.words[i]<==taskDigest[i];qHash.words[8+i]<==qSalt[i];
    }
    for(var s=0;s<S;s++) {
        countBits[s]=Num2Bits(8);countBits[s].in<==counts[s];
        countBound[s]=LessEqThan(8);countBound[s].in[0]<==counts[s];countBound[s].in[1]<==R;countBound[s].out===1;
        slotTree[s]=CoreSlots(R);coverage[s]=CoreOr(R);
        for(var r=0;r<R;r++) {
            exists[s][r]=LessThan(8);exists[s][r].in[0]<==r;exists[s][r].in[1]<==counts[s];
            rec[s][r]=CoreRecord();rec[s][r].enabled<==exists[s][r].out;
            for(var f=0;f<35;f++)rec[s][r].words[f]<==records[s][r][f];
            exists[s][r].out*(records[s][r][1]-sourceIds[s])===0;
            exists[s][r].out*(records[s][r][4]-objectId)===0;exists[s][r].out*(records[s][r][5]-evidenceType)===0;
            exists[s][r].out*(records[s][r][6]-r)===0;
            slotHash[s][r]=CoreHash(2,3,0);
            for(var l=0;l<2;l++)slotHash[s][r].words[l]<==rec[s][r].digest[l];
            for(var l=0;l<2;l++)slotTree[s].leaves[r][l]<==emptySlot.digest[l]+exists[s][r].out*(slotHash[s][r].digest[l]-emptySlot.digest[l]);
            lowerOK[s][r]=LessEqThan(64);lowerOK[s][r].in[0]<==lower[0]*4294967296+lower[1];lowerOK[s][r].in[1]<==records[s][r][7]*4294967296+records[s][r][8];
            upperOK[s][r]=LessThan(64);upperOK[s][r].in[0]<==records[s][r][7]*4294967296+records[s][r][8];upperOK[s][r].in[1]<==upper[0]*4294967296+upper[1];
            hitGate[s][r]=CoreAnd(3);hitGate[s][r].in[0]<==exists[s][r].out;hitGate[s][r].in[1]<==lowerOK[s][r].out;hitGate[s][r].in[2]<==upperOK[s][r].out;
            selected[s][r]*(selected[s][r]-1)===0;
            if(MODE==1)selected[s][r]*(1-hitGate[s][r].out)===0;
            else selected[s][r]===hitGate[s][r].out;
            coverage[s].in[r]<==selected[s][r];
            life[s][r]=IsEqual();life[s][r].in[0]<==records[s][r][15];life[s][r].in[1]<==1;
            assessment[s][r]=IsEqual();assessment[s][r].in[0]<==records[s][r][16];assessment[s][r].in[1]<==1;
            risk[s][r]=LessEqThan(32);risk[s][r].in[0]<==records[s][r][17];risk[s][r].in[1]<==maxRisk;
            fromOK[s][r]=LessEqThan(64);fromOK[s][r].in[0]<==records[s][r][11]*4294967296+records[s][r][12];fromOK[s][r].in[1]<==evaluation[0]*4294967296+evaluation[1];
            untilOK[s][r]=LessThan(64);untilOK[s][r].in[0]<==deadline[0]*4294967296+deadline[1];untilOK[s][r].in[1]<==records[s][r][13]*4294967296+records[s][r][14];
            purposeBits[s][r]=Num2Bits(32);purposeBits[s][r].in<==records[s][r][18];
            var purposeSum=0;
            for(var b=0;b<32;b++) {purposeEq[s][r][b]=IsEqual();purposeEq[s][r][b].in[0]<==purposeBit;purposeEq[s][r][b].in[1]<==b;
                purposeTerms[s][r][b]<==purposeEq[s][r][b].out*purposeBits[s][r].out[b];purposeSum+=purposeTerms[s][r][b];}
            purposeOK[s][r]<==purposeSum;
            validity[s][r]=CoreAnd(4);validity[s][r].in[0]<==life[s][r].out;validity[s][r].in[1]<==fromOK[s][r].out;validity[s][r].in[2]<==untilOK[s][r].out;validity[s][r].in[3]<==purposeOK[s][r];
            if(MODE==2)effectiveValid[s][r]<==1;else effectiveValid[s][r]<==validity[s][r].out;
            businessOK[s][r]=CoreAnd(3);businessOK[s][r].in[0]<==assessment[s][r].out;businessOK[s][r].in[1]<==risk[s][r].out;businessOK[s][r].in[2]<==effectiveValid[s][r];
            recordOK[s][r]<==1-selected[s][r]*(1-businessOK[s][r].out);allRecords.in[s*R+r]<==recordOK[s][r];
            qHash.words[16+(s*R+r)*3]<==selected[s][r];
            for(var l=0;l<2;l++)qHash.words[17+(s*R+r)*3+l]<==selected[s][r]*rec[s][r].digest[l];
        }
        sourceOK[s]<==1-requireEach*(1-coverage[s].out);allCoverage.in[s]<==sourceOK[s];
        bucket[s]=CoreHash(5,5,0);bucket[s].words[0]<==objectId;bucket[s].words[1]<==evidenceType;bucket[s].words[2]<==counts[s];
        for(var l=0;l<2;l++)bucket[s].words[3+l]<==slotTree[s].root[l];
        countZero[s]=IsZero();countZero[s].in<==counts[s];directory[s]=CorePath(48,7);directory[s].index<==objectId*65536+evidenceType;
        for(var l=0;l<2;l++) {directory[s].leaf[l]<==bucket[s].digest[l]+countZero[s].out*(emptyDir.digest[l]-bucket[s].digest[l]);
            for(var h=0;h<48;h++)directory[s].siblings[h][l]<==directoryPaths[s][h][l];}
        for(var l=0;l<2;l++)directory[s].root[l]===stateRoots[s][l];
    }
    for(var l=0;l<2;l++)qHash.digest[l]===qCommit[l];
    signal hasGroup[S];signal supportOK;
    if(MODE!=3) {
        component nodeBits[G][16];component rootEq[G];component derivedEq[G];component opEq[G][6];component order[G];
        component parentActive[G][4];component parentLimit[G];component parentZero[G];component parentOrder[G][3];
        component parentHash[G];component parentSaltBits[G][8];component nodeHash[G];component regPath[G];component seqLimit[G];
        component rootRecord[G];component rootSourceEq[G][S];signal rootSource[G][S];
        component eventHash[G];component logLeaf[G];component logPath[G];component eventLimit[G];signal selectedLength[G];signal selectedLog[G][2];
        component parentMatch[G][4][G];signal parentPick[G][4][G];signal edge[G][G];
        signal active[G];signal rootBit[G];signal last[G];signal reached[G];signal reachableTerms[G][G];component unreachable[G];
        component matches[G][S][R];component hashEq[G][S][R][2];component keyEq[G][S][R];component qualify[G][S][R];component eligible[G];
        signal qualified[G];signal supportFlag[G];component allSupport=CoreAnd(G);
        signal rootKey[G];component sameKey[G][G];component firstRoot[G];signal unique[G];
        signal finalLeafTerm[G][2];signal finalContentTerm[G][2];signal lastKind[G];signal lastOp[G];
        for(var i=0;i<G;i++)active[i]<==nodes[i][0];
        for(var i=0;i<G;i++) {
            active[i]*(active[i]-1)===0;
            if(i>0)active[i]*(1-active[i-1])===0;
            if(i==G-1)last[i]<==active[i];else last[i]<==active[i]*(1-active[i+1]);
            for(var f=0;f<18;f++)(1-active[i])*nodes[i][f]===0;
            for(var f=0;f<16;f++) {
                nodeBits[i][f]=Num2Bits(32);
                if(f<13)nodeBits[i][f].in<==nodes[i][f];else nodeBits[i][f].in<==nodes[i][f+2];
            }
            rootEq[i]=IsEqual();rootEq[i].in[0]<==nodes[i][1];rootEq[i].in[1]<==1;
            derivedEq[i]=IsEqual();derivedEq[i].in[0]<==nodes[i][1];derivedEq[i].in[1]<==2;
            rootEq[i].out+derivedEq[i].out===active[i];rootBit[i]<==rootEq[i].out;
            var opSum=0;for(var o=0;o<6;o++){opEq[i][o]=IsEqual();opEq[i][o].in[0]<==nodes[i][2];opEq[i][o].in[1]<==o+1;opSum+=opEq[i][o].out;}
            opSum===active[i];opEq[i][0].out===rootBit[i];
            parentLimit[i]=LessEqThan(32);parentLimit[i].in[0]<==nodes[i][15];parentLimit[i].in[1]<==4;parentLimit[i].out===1;
            rootBit[i]*nodes[i][15]===0;
            parentZero[i]=IsZero();parentZero[i].in<==nodes[i][15];parentZero[i].out*(derivedEq[i].out-opEq[i][5].out)===0;
            if(i>0){order[i]=LessThan(32);order[i].in[0]<==nodes[i-1][3];order[i].in[1]<==nodes[i][3];active[i]*(1-order[i].out)===0;}
            seqLimit[i]=LessEqThan(32);seqLimit[i].in[0]<==nodes[i][3];seqLimit[i].in[1]<==registryLength;active[i]*(1-seqLimit[i].out)===0;
            parentHash[i]=CoreHash(13,12,0);parentHash[i].words[0]<==nodes[i][15];
            for(var p=0;p<4;p++) {
                parentActive[i][p]=LessThan(32);parentActive[i][p].in[0]<==p;parentActive[i][p].in[1]<==nodes[i][15];
                (1-parentActive[i][p].out)*parents[i][p]===0;parentHash[i].words[1+p]<==parents[i][p];
                if(p>0){parentOrder[i][p-1]=LessThan(32);parentOrder[i][p-1].in[0]<==parents[i][p-1];parentOrder[i][p-1].in[1]<==parents[i][p];parentActive[i][p].out*(1-parentOrder[i][p-1].out)===0;}
                var found=0;
                for(var j=0;j<G;j++) {
                    if(j<i) {parentMatch[i][p][j]=IsEqual();parentMatch[i][p][j].in[0]<==parents[i][p];parentMatch[i][p][j].in[1]<==nodes[j][3];parentPick[i][p][j]<==parentMatch[i][p][j].out*active[j];}
                    else parentPick[i][p][j]<==0;
                    found+=parentPick[i][p][j];
                }
                found===parentActive[i][p].out;
            }
            for(var j=0;j<G;j++){var incoming=0;for(var p=0;p<4;p++)incoming+=parentPick[i][p][j];edge[i][j]<==incoming;}
            for(var w=0;w<8;w++) {parentSaltBits[i][w]=Num2Bits(32);parentSaltBits[i][w].in<==parentSalts[i][w];(1-active[i])*parentSalts[i][w]===0;parentHash[i].words[5+w]<==parentSalts[i][w];}
            rootRecord[i]=CoreRecord();rootRecord[i].enabled<==rootBit[i];for(var f=0;f<35;f++)rootRecord[i].words[f]<==rootRecords[i][f];
            for(var l=0;l<2;l++)rootBit[i]*(nodes[i][13+l]-rootRecord[i].digest[l])===0;
            rootKey[i]<==rootRecords[i][1]*18446744073709551616+rootRecords[i][2]*4294967296+rootRecords[i][3];
            var foundSource=0;var len=0;
            for(var s=0;s<S;s++) {
                rootSourceEq[i][s]=IsEqual();rootSourceEq[i][s].in[0]<==rootRecords[i][1];rootSourceEq[i][s].in[1]<==sourceIds[s];
                rootSource[i][s]<==rootSourceEq[i][s].out*rootBit[i];foundSource+=rootSource[i][s];
            }
            foundSource===rootBit[i];
            // Source selection products have their own constrained signals below.
            nodeHash[i]=CoreHash(26,13,0);
            for(var f=0;f<18;f++)nodeHash[i].words[f]<==nodes[i][f];
            for(var l=0;l<2;l++)nodeHash[i].words[18+l]<==parentHash[i].digest[l];
            nodeHash[i].words[20]<==rootRecords[i][1];nodeHash[i].words[21]<==rootRecords[i][2];nodeHash[i].words[22]<==rootRecords[i][3];nodeHash[i].words[23]<==eventSeq[i];
            for(var l=0;l<2;l++)nodeHash[i].words[24+l]<==rootBit[i]*rootRecord[i].digest[l];
            regPath[i]=CorePath(32,17);regPath[i].index<==active[i]*(nodes[i][3]-1);
            for(var l=0;l<2;l++){regPath[i].leaf[l]<==nodeHash[i].digest[l];for(var h=0;h<32;h++)regPath[i].siblings[h][l]<==registryPaths[i][h][l];}
            for(var l=0;l<2;l++)active[i]*(regPath[i].root[l]-registryRoot[l])===0;
            for(var f=0;f<4;f++)(1-rootBit[i])*eventMeta[i][f]===0;(1-rootBit[i])*eventSeq[i]===0;
            eventHash[i]=CoreHash(6,8,0);for(var f=0;f<4;f++)eventHash[i].words[f]<==eventMeta[i][f];
            for(var l=0;l<2;l++)eventHash[i].words[4+l]<==rootRecord[i].digest[l];
            logLeaf[i]=CoreHash(3,9,0);logLeaf[i].words[0]<==eventSeq[i];for(var l=0;l<2;l++)logLeaf[i].words[l+1]<==eventHash[i].digest[l];
            logPath[i]=CorePath(32,11);logPath[i].index<==rootBit[i]*(eventSeq[i]-1);
            for(var l=0;l<2;l++){logPath[i].leaf[l]<==logLeaf[i].digest[l];for(var h=0;h<32;h++)logPath[i].siblings[h][l]<==logPaths[i][h][l];}
            eligible[i]=CoreOr(S*R);
            for(var s=0;s<S;s++)for(var r=0;r<R;r++) {
                keyEq[i][s][r]=IsEqual();
                if(MODE==2){keyEq[i][s][r].in[0]<==rootRecords[i][1]*4294967296+rootRecords[i][2];keyEq[i][s][r].in[1]<==records[s][r][1]*4294967296+records[s][r][2];}
                else {keyEq[i][s][r].in[0]<==rootKey[i];keyEq[i][s][r].in[1]<==records[s][r][1]*18446744073709551616+records[s][r][2]*4294967296+records[s][r][3];}
                for(var l=0;l<2;l++){hashEq[i][s][r][l]=IsEqual();hashEq[i][s][r][l].in[0]<==rootRecord[i].digest[l];hashEq[i][s][r][l].in[1]<==rec[s][r].digest[l];}
                qualify[i][s][r]=CoreAnd(5);qualify[i][s][r].in[0]<==selected[s][r];qualify[i][s][r].in[1]<==keyEq[i][s][r].out;
                if(MODE==2){qualify[i][s][r].in[2]<==1;qualify[i][s][r].in[3]<==1;}
                else {qualify[i][s][r].in[2]<==hashEq[i][s][r][0].out;qualify[i][s][r].in[3]<==hashEq[i][s][r][1].out;}
                qualify[i][s][r].in[4]<==effectiveValid[s][r];eligible[i].in[s*R+r]<==qualify[i][s][r].out;
            }
            qualified[i]<==rootBit[i]*eligible[i].out;supportFlag[i]<==1-rootBit[i]*(1-eligible[i].out);allSupport.in[i]<==supportFlag[i];
            firstRoot[i]=CoreAnd(G);
            for(var j=0;j<G;j++) {
                if(j<i){sameKey[i][j]=IsEqual();sameKey[i][j].in[0]<==rootKey[i];sameKey[i][j].in[1]<==rootKey[j];
                    firstRoot[i].in[j]<==1-sameKey[i][j].out*rootBit[j];}
                else firstRoot[i].in[j]<==1;
            }
            unique[i]<==rootBit[i]*firstRoot[i].out;
            for(var l=0;l<2;l++){finalLeafTerm[i][l]<==last[i]*nodeHash[i].digest[l];finalContentTerm[i][l]<==last[i]*nodes[i][13+l];}
            lastKind[i]<==last[i]*nodes[i][1];lastOp[i]<==last[i]*nodes[i][2];
        }
        signal logTerms[G][S][2];signal lengthTerms[G][S];
        for(var i=0;i<G;i++) {
            var len=0;for(var s=0;s<S;s++){lengthTerms[i][s]<==rootSource[i][s]*logLengths[s];len+=lengthTerms[i][s];}selectedLength[i]<==len;
            eventLimit[i]=LessEqThan(32);eventLimit[i].in[0]<==eventSeq[i];eventLimit[i].in[1]<==selectedLength[i];rootBit[i]*(1-eventLimit[i].out)===0;
            for(var l=0;l<2;l++){var sum=0;for(var s=0;s<S;s++){logTerms[i][s][l]<==rootSource[i][s]*logRoots[s][l];sum+=logTerms[i][s][l];}selectedLog[i][l]<==sum;rootBit[i]*(logPath[i].root[l]-selectedLog[i][l])===0;}
        }
        for(var i=G-1;i>=0;i--) {
            unreachable[i]=CoreAnd(G+1);unreachable[i].in[0]<==1-last[i];
            for(var j=0;j<G;j++) {
                if(j>i)reachableTerms[i][j]<==reached[j]*edge[j][i];else reachableTerms[i][j]<==0;
                unreachable[i].in[j+1]<==1-reachableTerms[i][j];
            }
            reached[i]<==1-unreachable[i].out;reached[i]===active[i];
        }
        var lastCount=0;var kinds=0;var ops=0;for(var i=0;i<G;i++){lastCount+=last[i];kinds+=lastKind[i];ops+=lastOp[i];}
        lastCount===1;kinds===2;ops===6;
        for(var l=0;l<2;l++){var sum=0;var content=0;for(var i=0;i<G;i++){sum+=finalLeafTerm[i][l];content+=finalContentTerm[i][l];}sum===handoffNode[l];content===handoffCommit[l];}
        component sortedMatch[G][G];signal sortedMatchActive[G][G];component rootOrder[G-1];
        signal sortedKey[G];component sortedWordBits[G][3];component lHash=CoreHash(16+6*G,19,0);
        for(var w=0;w<8;w++){lHash.words[w]<==taskDigest[w];lHash.words[8+w]<==lSalt[w];}
        for(var j=0;j<G;j++) {
            for(var f=0;f<3;f++){sortedWordBits[j][f]=Num2Bits(32);sortedWordBits[j][f].in<==sortedRoots[j][f+1];}
            sortedRoots[j][0]*(sortedRoots[j][0]-1)===0;
            if(j>0)sortedRoots[j][0]*(1-sortedRoots[j-1][0])===0;
            for(var f=1;f<6;f++)(1-sortedRoots[j][0])*sortedRoots[j][f]===0;
            sortedKey[j]<==sortedRoots[j][1]*18446744073709551616+sortedRoots[j][2]*4294967296+sortedRoots[j][3];
            if(j>0){rootOrder[j-1]=LessThan(96);rootOrder[j-1].in[0]<==sortedKey[j-1];rootOrder[j-1].in[1]<==sortedKey[j];sortedRoots[j][0]*(1-rootOrder[j-1].out)===0;}
            var found=0;
            for(var i=0;i<G;i++) {
                sortedMatch[j][i]=IsEqual();sortedMatch[j][i].in[0]<==sortedKey[j];sortedMatch[j][i].in[1]<==rootKey[i];
                sortedMatchActive[j][i]<==sortedMatch[j][i].out*unique[i];found+=sortedMatchActive[j][i];
                for(var l=0;l<2;l++)sortedMatchActive[j][i]*(sortedRoots[j][4+l]-rootRecord[i].digest[l])===0;
            }
            found===sortedRoots[j][0];for(var f=0;f<6;f++)lHash.words[16+j*6+f]<==sortedRoots[j][f];
        }
        for(var i=0;i<G;i++){var count=0;for(var j=0;j<G;j++)count+=sortedMatchActive[j][i];count===unique[i];}
        for(var l=0;l<2;l++)lHash.digest[l]===lCommit[l];
        component sourceRoot[S];signal sourceRootTerms[S][G];
        for(var s=0;s<S;s++){sourceRoot[s]=CoreOr(G);for(var i=0;i<G;i++){sourceRootTerms[s][i]<==qualified[i]*rootSource[i][s];sourceRoot[s].in[i]<==sourceRootTerms[s][i];}hasGroup[s]<==sourceRoot[s].out;}
        supportOK<==allSupport.out;
    } else {
        for(var s=0;s<S;s++){claimedGroups[s]*(claimedGroups[s]-1)===0;hasGroup[s]<==claimedGroups[s];}
        supportOK<==1;
    }
    component sameGroup[S][S];component firstGroup[S];signal groups[S];
    for(var s=0;s<S;s++) {
        firstGroup[s]=CoreAnd(S);
        for(var t=0;t<S;t++) {
            if(t<s){sameGroup[s][t]=IsEqual();sameGroup[s][t].in[0]<==sourceGroups[s];sameGroup[s][t].in[1]<==sourceGroups[t];firstGroup[s].in[t]<==1-sameGroup[s][t].out*hasGroup[t];}
            else firstGroup[s].in[t]<==1;
        }
        groups[s]<==hasGroup[s]*firstGroup[s].out;
    }
    var groupCount=0;for(var s=0;s<S;s++)groupCount+=groups[s];
    component enough=LessEqThan(32);enough.in[0]<==minGroups;enough.in[1]<==groupCount;
    signal p;signal s;p<==allCoverage.out*allRecords.out;s<==supportOK*enough.out;
    decision===p*s;reason===1-p+2*p*(1-s);
}
