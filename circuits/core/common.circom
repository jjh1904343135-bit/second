pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mimcsponge.circom";

// All roots are TWO native BN254 scalars. Metadata SHA256 bytes are never
// reduced modulo Fr; their original bytes enter the fixed-width word encoding.
template CoreHash(N,kind,level) {
    signal input words[N];signal output digest[2];
    assert(N<16777216);assert(level<16777216);
    // Injective domain/length encoding in the public permutation key; no rounds
    // or digest limbs are removed. Empty messages use a distinguished zero block.
    var L=N;if(N==0)L=1;
    component h=MiMCSponge(L,220,2);
    h.k<==1380141126+kind*281474976710656+level*16777216+N;
    if(N==0)h.ins[0]<==0;
    for(var i=0;i<N;i++)h.ins[i]<==words[i];
    digest[0]<==h.outs[0];digest[1]<==h.outs[1];
}
template CorePath(D,kind) {
    signal input leaf[2];signal input index;signal input siblings[D][2];
    signal output root[2];signal running[D+1][2];signal left[D][2];signal right[D][2];
    component bits=Num2Bits(D);bits.in<==index;component hashes[D];
    for(var l=0;l<2;l++)running[0][l]<==leaf[l];
    for(var h=0;h<D;h++) {
        hashes[h]=CoreHash(4,kind,h);
        for(var l=0;l<2;l++) {
            left[h][l]<==running[h][l]+bits.out[h]*(siblings[h][l]-running[h][l]);
            right[h][l]<==siblings[h][l]+bits.out[h]*(running[h][l]-siblings[h][l]);
            hashes[h].words[l]<==left[h][l];hashes[h].words[2+l]<==right[h][l];
        }
        for(var l=0;l<2;l++)running[h+1][l]<==hashes[h].digest[l];
    }
    for(var l=0;l<2;l++)root[l]<==running[D][l];
}
template CoreRecord() {
    signal input enabled;signal input words[35];signal output digest[2];
    component bounds[35];component hash=CoreHash(35,1,0);
    var widths[35]=[16,32,32,32,32,16,8,32,32,32,32,32,32,32,32,8,8,16,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32];
    enabled*(enabled-1)===0;words[0]===enabled;
    for(var i=0;i<35;i++) {
        bounds[i]=Num2Bits(widths[i]);bounds[i].in<==words[i];
        (1-enabled)*words[i]===0;hash.words[i]<==words[i];
    }
    component lifeLow=LessEqThan(8);lifeLow.in[0]<==1;lifeLow.in[1]<==words[15];lifeLow.out===enabled;
    component lifeHigh=LessEqThan(8);lifeHigh.in[0]<==words[15];lifeHigh.in[1]<==2;lifeHigh.out===1;
    component assessLow=LessEqThan(8);assessLow.in[0]<==1;assessLow.in[1]<==words[16];assessLow.out===enabled;
    component assessHigh=LessEqThan(8);assessHigh.in[0]<==words[16];assessHigh.in[1]<==3;assessHigh.out===1;
    component risk=LessEqThan(16);risk.in[0]<==words[17];risk.in[1]<==10000;risk.out===1;
    component chronological=LessEqThan(64);chronological.in[0]<==words[7]*4294967296+words[8];chronological.in[1]<==words[9]*4294967296+words[10];chronological.out===1;
    component window=LessThan(64);window.in[0]<==words[11]*4294967296+words[12];window.in[1]<==words[13]*4294967296+words[14];window.out===enabled;
    for(var l=0;l<2;l++)digest[l]<==hash.digest[l];
}
template CoreSlots(R) {
    signal input leaves[R][2];signal output root[2];
    signal nodes[2*R-1][2];component hashes[R-1];
    for(var i=0;i<R;i++)for(var l=0;l<2;l++)nodes[R-1+i][l]<==leaves[i][l];
    for(var i=R-2;i>=0;i--) {
        var level=0;var width=R;var rowStart=R-1;
        while(i<rowStart){width=width\2;rowStart=width-1;level++;}
        hashes[i]=CoreHash(4,4,level-1);
        for(var l=0;l<2;l++) {hashes[i].words[l]<==nodes[2*i+1][l];hashes[i].words[l+2]<==nodes[2*i+2][l];}
        for(var l=0;l<2;l++)nodes[i][l]<==hashes[i].digest[l];
    }
    for(var l=0;l<2;l++)root[l]<==nodes[0][l];
}
template CoreAnd(N) {
    signal input in[N];signal output out;signal accum[N+1];accum[0]<==1;
    for(var i=0;i<N;i++)accum[i+1]<==accum[i]*in[i];out<==accum[N];
}
template CoreOr(N) {
    signal input in[N];signal output out;signal accum[N+1];accum[0]<==1;
    for(var i=0;i<N;i++)accum[i+1]<==accum[i]*(1-in[i]);out<==1-accum[N];
}
