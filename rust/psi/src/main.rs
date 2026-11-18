//! Nova's native StepCircuit imports the actual Circom R1CS, not a validity bit.
//! Outputs are wires 1..arity; old-state inputs alias Nova's recursive z wires.
use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError, Variable},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{Bn256EngineIPA, GrumpkinEngine, ipa_pc::EvaluationEngine},
    spartan::ppsnark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::{fs, io::{Read,Write,BufRead,Seek,SeekFrom,BufReader}, path::Path, sync::Arc, time::Instant, os::unix::{net::UnixListener,fs::PermissionsExt}};

type E1 = Bn256EngineIPA;
type E2 = GrumpkinEngine;
type F = <E1 as Engine>::Scalar;
type S1 = RelaxedR1CSSNARK<E1, EvaluationEngine<E1>>;
type S2 = RelaxedR1CSSNARK<E2, EvaluationEngine<E2>>;
type PP = PublicParams<E1,E2,Imported>;
type Rec = RecursiveSNARK<E1,E2,Imported>;
type Proof = CompressedSNARK<E1,E2,Imported,S1,S2>;
type PK = nova_snark::nova::ProverKey<E1,E2,Imported,S1,S2>;
type VK = nova_snark::nova::VerifierKey<E1,E2,Imported,S1,S2>;
type LC = Vec<(usize,F)>;
type Error = Box<dyn std::error::Error>;
const ARITY: usize = 7;

fn u32le(r: &mut impl Read) -> Result<u32,Error> {let mut b=[0;4];r.read_exact(&mut b)?;Ok(u32::from_le_bytes(b))}
fn u64le(r: &mut impl Read) -> Result<u64,Error> {let mut b=[0;8];r.read_exact(&mut b)?;Ok(u64::from_le_bytes(b))}
fn scalar(r: &mut impl Read) -> Result<F,Error> {
    let mut repr=<F as PrimeField>::Repr::default();r.read_exact(repr.as_mut())?;
    Option::<F>::from(F::from_repr(repr)).ok_or("NON_CANONICAL_FIELD".into())
}
fn parse(s:&str)->Result<F,Error> {F::from_str_vartime(s).ok_or("INVALID_FIELD".into())}
fn display(v:&F)->String {
    // Explicit decimal conversion; no reduction of non-canonical wire encodings.
    let mut digits=vec![0u8];
    for b in v.to_repr().as_ref().iter().rev() {
        let mut carry=*b as u32;
        for d in &mut digits {let n=(*d as u32)*256+carry;*d=(n%10) as u8;carry=n/10;}
        while carry>0 {digits.push((carry%10) as u8);carry/=10;}
    }
    digits.iter().rev().map(|d|(b'0'+d) as char).collect()
}
fn sections(file:&str, magic:&[u8;4])->Result<(BufReader<fs::File>,Vec<(u32,u64,u64)>),Error> {
    let mut r=BufReader::new(fs::File::open(file)?);let mut m=[0;4];r.read_exact(&mut m)?;
    if &m!=magic {return Err("BINARY_MAGIC".into());}
    let _version=u32le(&mut r)?;let n=u32le(&mut r)?;let mut out=vec![];
    for _ in 0..n {let kind=u32le(&mut r)?;let len=u64le(&mut r)?;let offset=r.stream_position()?;
        out.push((kind,offset,len));r.seek(SeekFrom::Current(len as i64))?;}
    Ok((r,out))
}
#[derive(Debug)]
struct Shape {vars:usize,constraints:Vec<[LC;3]>,digest:String}
impl Shape {
    fn read(file:&str)->Result<Self,Error> {
        let digest=hex::encode(Sha256::digest(fs::read(file)?));
        let (mut r,s)=sections(file,b"r1cs")?;
        r.seek(SeekFrom::Start(s.iter().find(|x|x.0==1).ok_or("R1CS_HEADER")?.1))?;
        if u32le(&mut r)?!=32 {return Err("FIELD_BYTES".into());}
        let mut p=[0;32];r.read_exact(&mut p)?;
        // Prime must be the BN254 scalar field, not the base/Grumpkin field.
        let minus=F::ZERO-F::ONE;let mut expected=minus.to_repr().as_ref().to_vec();
        let mut carry=1u16;for b in &mut expected {let n=*b as u16+carry;*b=n as u8;carry=n>>8;}
        if p.as_slice()!=expected.as_slice() {return Err("R1CS_FIELD_MISMATCH".into());}
        let vars=u32le(&mut r)? as usize;let outputs=u32le(&mut r)? as usize;let public=u32le(&mut r)? as usize;
        let _private=u32le(&mut r)?;let _labels=u64le(&mut r)?;let n=u32le(&mut r)? as usize;
        if outputs!=ARITY||public!=ARITY {return Err("R1CS_STATE_LAYOUT".into());}
        r.seek(SeekFrom::Start(s.iter().find(|x|x.0==2).ok_or("R1CS_CONSTRAINTS")?.1))?;
        let mut constraints=Vec::with_capacity(n);
        for _ in 0..n {
            let mut c:[LC;3]=[vec![],vec![],vec![]];
            for lc in &mut c {let k=u32le(&mut r)?;lc.reserve(k as usize);
                for _ in 0..k {let wire=u32le(&mut r)? as usize;let coefficient=scalar(&mut r)?;
                    if wire>=vars {return Err("R1CS_WIRE".into());}lc.push((wire,coefficient));}}
            constraints.push(c);
        }
        Ok(Self{vars,constraints,digest})
    }
}
fn witness(file:&str)->Result<Vec<F>,Error> {
    let (mut r,s)=sections(file,b"wtns")?;
    let section=s.iter().find(|x|x.0==2).ok_or("WTNS_VALUES")?;
    r.seek(SeekFrom::Start(section.1))?;
    (0..section.2/32).map(|_|scalar(&mut r)).collect()
}
#[derive(Clone,Debug)]
struct Imported {shape:Arc<Shape>,witness:Option<Arc<Vec<F>>>}
fn combination(lc:&LC, wires:&[Variable])->LinearCombination<F> {
    lc.iter().fold(LinearCombination::zero(),|sum,(i,c)|sum+(*c,wires[*i]))
}
impl StepCircuit<F> for Imported {
    fn arity(&self)->usize {ARITY}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError> {
        let mut wires=Vec::with_capacity(self.shape.vars);wires.push(CS::one());
        let mut outputs=vec![];
        for i in 1..self.shape.vars {
            if (1+ARITY..1+2*ARITY).contains(&i) {wires.push(z[i-1-ARITY].get_variable());}
            else {
                let allocated=AllocatedNum::alloc(cs.namespace(||format!("wire_{i}")),|| {
                    self.witness.as_ref().map(|w|w[i]).ok_or(SynthesisError::AssignmentMissing)
                })?;
                wires.push(allocated.get_variable());if i<=ARITY {outputs.push(allocated);}
            }
        }
        for (i,c) in self.shape.constraints.iter().enumerate() {
            cs.enforce(||format!("r1cs_{i}"),|_|combination(&c[0],&wires),|_|combination(&c[1],&wires),|_|combination(&c[2],&wires));
        }
        Ok(outputs)
    }
}
fn read_bin<T:serde::de::DeserializeOwned>(file:&Path)->Result<T,Error> {
    let bytes=fs::read(file)?;let (value,n)=bincode::serde::decode_from_slice(&bytes,bincode::config::legacy())?;
    if n!=bytes.len(){return Err("BINARY_TRAILING_BYTES".into());}Ok(value)
}
fn write_bin<T:Serialize>(file:&Path,value:&T)->Result<(),Error> {
    fs::write(file,bincode::serde::encode_to_vec(value,bincode::config::legacy())?)?;Ok(())
}
#[derive(Serialize,Deserialize)]
struct Saved {r1cs:String,z0:Vec<F>,ivc:Rec}
#[derive(Deserialize)]
struct Job {
    z0:Vec<String>,witnesses:Vec<String>,checkpoint_in:Option<String>,checkpoint_out:String,proof_out:String,
}
#[derive(Serialize,Deserialize)]
struct Statement {num_steps:usize,z0:Vec<String>,output:Vec<String>}
#[derive(Deserialize)]
struct VerifyRequest {id:String,statement:Statement,proof_hex:String}
fn verify_one(vk:&VK,statement:&Statement,proof:&Proof)->Result<serde_json::Value,Error> {
    if statement.z0.len()!=ARITY||statement.output.len()!=ARITY||statement.num_steps==0{return Err("STATEMENT_LAYOUT".into());}
    let z0=statement.z0.iter().map(|s|parse(s)).collect::<Result<Vec<_>,_>>()?;
    let start=Instant::now();let actual=proof.verify(vk,statement.num_steps,&z0)?;
    let expected=statement.output.iter().map(|s|parse(s)).collect::<Result<Vec<_>,_>>()?;
    if actual!=expected{return Err("PUBLIC_STATE_MISMATCH".into());}
    Ok(serde_json::json!({"verified":true,"verify_ms":start.elapsed().as_secs_f64()*1000.}))
}
fn serve(params:&str,socket:&str)->Result<serde_json::Value,Error> {
    let start=Instant::now();let file=Path::new(params).join("vk.bin");
    let vk_id=hex::encode(Sha256::digest(fs::read(&file)?));let vk:VK=read_bin(&file)?;
    let listener=UnixListener::bind(socket)?;fs::set_permissions(socket,fs::Permissions::from_mode(0o600))?;
    println!("{}",serde_json::json!({"ready":true,"vk_id":vk_id,"key_load_ms":start.elapsed().as_secs_f64()*1000.}));std::io::stdout().flush()?;
    for connection in listener.incoming() {
        let mut stream=connection?;let mut line=String::new();BufReader::new(&stream).take(262144).read_line(&mut line)?;
        let response=(||->Result<serde_json::Value,Error>{
            let request:VerifyRequest=serde_json::from_str(&line)?;let bytes=hex::decode(request.proof_hex)?;
            let (proof,n):(Proof,usize)=bincode::serde::decode_from_slice(&bytes,bincode::config::legacy())?;
            if n!=bytes.len(){return Err("BINARY_TRAILING_BYTES".into());}
            let mut result=verify_one(&vk,&request.statement,&proof)?;
            result["id"]=serde_json::json!(request.id);result["vk_id"]=serde_json::json!(vk_id);Ok(result)
        })().unwrap_or_else(|e|serde_json::json!({"verified":false,"error":e.to_string(),"vk_id":vk_id}));
        writeln!(stream,"{response}")?;
    }
    Ok(serde_json::json!({"status":"STOPPED"}))
}

fn main_work()->Result<serde_json::Value,Error> {
    let args:Vec<String>=std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup")=> {
            let shape=Arc::new(Shape::read(&args[2])?);let dir=Path::new(&args[3]);fs::create_dir_all(dir)?;
            let circuit=Imported{shape:shape.clone(),witness:None};let start=Instant::now();
            let pp=PP::setup(&circuit,&*S1::ck_floor(),&*S2::ck_floor())?;
            let constraints=pp.num_constraints();
            let (pk,vk)=Proof::setup(&pp)?;
            write_bin(&dir.join("pp.bin"),&pp)?;write_bin(&dir.join("pk.bin"),&pk)?;write_bin(&dir.join("vk.bin"),&vk)?;
            fs::write(dir.join("r1cs.sha256"),&shape.digest)?;
            Ok(serde_json::json!({"status":"PASS","setup_ms":start.elapsed().as_secs_f64()*1000.,"constraints":constraints,"r1cs":shape.digest}))
        },
        Some("prove")=> {
            let shape=Arc::new(Shape::read(&args[2])?);let dir=Path::new(&args[3]);
            if fs::read_to_string(dir.join("r1cs.sha256"))?!=shape.digest {return Err("PARAMETER_SHAPE_MISMATCH".into());}
            let pp:PP=read_bin(&dir.join("pp.bin"))?;let pk:PK=read_bin(&dir.join("pk.bin"))?;
            let job:Job=serde_json::from_slice(&fs::read(&args[4])?)?;
            let z0:Vec<F>=job.z0.iter().map(|s|parse(s)).collect::<Result<_,_>>()?;
            if z0.len()!=ARITY {return Err("GENESIS_ARITY".into());}
            let mut ivc:Option<Rec>=if let Some(file)=job.checkpoint_in {
                let saved:Saved=read_bin(Path::new(&file))?;
                if saved.r1cs!=shape.digest||saved.z0!=z0 {return Err("CHECKPOINT_BINDING".into());}Some(saved.ivc)
            }else{None};
            let start=Instant::now();
            for file in &job.witnesses {
                let w=witness(file)?;
                if w.len()!=shape.vars||w[0]!=F::ONE {return Err("WITNESS_LAYOUT".into());}
                let current=ivc.as_ref().map(|r|r.outputs()).unwrap_or(&z0);
                if w[1+ARITY..1+2*ARITY]!=*current {return Err("STEP_CHAIN_BINDING".into());}
                let circuit=Imported{shape:shape.clone(),witness:Some(Arc::new(w))};
                if ivc.is_none() {ivc=Some(Rec::new(&pp,&circuit,&z0)?);}
                ivc.as_mut().unwrap().prove_step(&pp,&circuit)?;
                eprintln!("NOVA_FOLD step={} elapsed_ms={:.3}",ivc.as_ref().unwrap().num_steps(),start.elapsed().as_secs_f64()*1000.);
            }
            let ivc=ivc.ok_or("EMPTY_HISTORY_REQUIRES_CANONICAL_MARKER")?;
            let fold_ms=start.elapsed().as_secs_f64()*1000.;
            // Compression is the official randomized, zero-knowledge export path.
            let start=Instant::now();let proof=Proof::prove(&pp,&pk,&ivc)?;
            let export_ms=start.elapsed().as_secs_f64()*1000.;
            let vk:VK=read_bin(&dir.join("vk.bin"))?;let start=Instant::now();
            let output=proof.verify(&vk,ivc.num_steps(),&z0)?;
            let verify_ms=start.elapsed().as_secs_f64()*1000.;
            let statement=Statement{num_steps:ivc.num_steps(),z0:job.z0,output:output.iter().map(display).collect()};
            write_bin(Path::new(&job.proof_out),&proof)?;
            write_bin(Path::new(&job.checkpoint_out),&Saved{r1cs:shape.digest.clone(),z0,ivc})?;
            Ok(serde_json::json!({"status":"PASS","fold_ms":fold_ms,"export_ms":export_ms,"verify_ms":verify_ms,"statement":statement,"proof_bytes":fs::metadata(&job.proof_out)?.len()}))
        },
        Some("verify")=> {
            let vk:VK=read_bin(&Path::new(&args[2]).join("vk.bin"))?;
            let statement:Statement=serde_json::from_slice(&fs::read(&args[3])?)?;
            let proof:Proof=read_bin(Path::new(&args[4]))?;
            verify_one(&vk,&statement,&proof)
        },
        Some("serve")=>serve(&args[2],&args[3]),
        Some("hash-vectors")=> {
            let value:serde_json::Value=serde_json::from_slice(&fs::read(&args[2])?)?;
            let constants=value["constants"].as_array().ok_or("MIMC_CONSTANTS")?.iter().map(|v|parse(v.as_str().unwrap())).collect::<Result<Vec<_>,_>>()?;
            if constants.len()!=220 {return Err("MIMC_ROUNDS".into());}
            let permutation=|mut left:F,mut right:F,key:F| {
                for (i,c) in constants.iter().enumerate() {
                    let t=left+key+c;let t5=t.square().square()*t;
                    if i<219 {let new_left=right+t5;right=left;left=new_left;}else{right+=t5;}
                }(left,right)
            };
            let mut results=vec![];
            for v in value["vectors"].as_array().ok_or("MIMC_VECTORS")? {
                let words=v["words"].as_array().ok_or("MIMC_WORDS")?;
                let key=F::from(1380141126u64)+parse(v["kind"].as_str().unwrap())?*F::from(281474976710656u64)
                    +parse(v["level"].as_str().unwrap())?*F::from(16777216u64)+F::from(words.len() as u64);
                let mut inputs=vec![];
                for w in words {inputs.push(parse(w.as_str().unwrap())?);}
                if inputs.is_empty(){inputs.push(F::ZERO);}
                let (mut left,mut right)=(F::ZERO,F::ZERO);
                for input in inputs {(left,right)=permutation(left+input,right,key);}
                let first=left;let (second,_)=permutation(left,right,key);
                let actual=vec![display(&first),display(&second)];
                let expected=v["expected"].as_array().unwrap().iter().map(|x|x.as_str().unwrap().to_string()).collect::<Vec<_>>();
                if actual!=expected {return Err("RUST_JS_MIMC_MISMATCH".into());}
                results.push(actual);
            }
            Ok(serde_json::json!({"status":"PASS","vectors":results}))
        },
        _=>Err("usage: rcpeh-psi setup R1CS DIR | prove R1CS DIR JOB | verify DIR STATEMENT PROOF".into()),
    }
}
fn main() {
    match main_work() {
        Ok(value)=>println!("{value}"),
        Err(error)=>{eprintln!("{error}");println!("{}",serde_json::json!({"verified":false,"error":error.to_string()}));std::process::exit(1);}
    }
}
