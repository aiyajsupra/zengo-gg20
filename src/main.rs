use std::collections::HashMap;
use curv::arithmetic::{BigInt, Converter};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, LocalKey, ProtocolMessage};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{CompletedOfflineStage, OfflineProtocolMessage, OfflineStage, SignManual};
use round_based::{Msg, StateMachine};


fn main() {
    let total_parties = 4 as u16;
    let total_threshold = 2 as u16;

    let mut keygen_vec = vec![];
    let mut local_key_vec = vec![];
    run_keygen(total_parties, total_threshold, &mut keygen_vec, &mut local_key_vec);

    run_signing(total_parties, total_threshold, &mut keygen_vec, &mut local_key_vec);
}

fn broadcast_msg(msgs_vec: &mut Vec<Msg<ProtocolMessage>>, keygen_vec: &mut Vec<Keygen>)
{
    for (k,v) in msgs_vec.iter().enumerate() {
        for (i, keygen) in keygen_vec.iter_mut().enumerate() {
            if k != i {
                keygen.handle_incoming(v.clone());
            }
        }
    }
}

fn p2p_msg(p2p_msg_hashmap: &mut HashMap<usize ,Vec<Msg<ProtocolMessage>>>, keygen_vec: &mut Vec<Keygen>)
{
    for (party_index, msg_vec) in p2p_msg_hashmap {
        for msg in msg_vec
        {
            let receiver = msg.receiver.unwrap();
            keygen_vec[(receiver - 1) as usize].handle_incoming(msg.clone());
        }
    }
}

fn run_keygen(total_parties: u16, total_threshold: u16, keygen_vec: &mut Vec<Keygen>,local_key_vec: &mut Vec<LocalKey>)
{
    // generating parties
    for i in 1..=total_parties {
        keygen_vec.push(Keygen::new(i,total_threshold,total_parties).unwrap());
    }

    // for getting messages after each round
    let mut msgs_vec = vec![];

    //For round 1 messages;
    for i in keygen_vec.iter_mut() {
        i.proceed();
        msgs_vec.push(i.message_queue()[0].clone());
    }
    println!("keygen 1:{:?}", &keygen_vec[0]);
    println!("keygen 2:{:?}", &keygen_vec[1]);
    println!("keygen 3:{:?}", &keygen_vec[2]);
    println!("keygen 4:{:?}", &keygen_vec[3]);

    //Broadcast each message to each parties
    broadcast_msg(&mut msgs_vec, keygen_vec);

    println!("keygen 1:{:?}", &keygen_vec[0]);
    println!("keygen 2:{:?}", &keygen_vec[1]);
    println!("keygen 3:{:?}", &keygen_vec[2]);
    println!("keygen 4:{:?}", &keygen_vec[3]);

    msgs_vec.clear();
    // for round 2
    for i in keygen_vec.iter_mut() {
        msgs_vec.push(i.message_queue()[1].clone());
    }

    broadcast_msg(&mut msgs_vec, keygen_vec);

    for keygen in keygen_vec.iter_mut() {
        keygen.proceed();
    }

    // for round 3
    msgs_vec.clear();
    let mut p2p_msg_hashmap = HashMap::new();
    for (party_index,keygen) in keygen_vec.iter_mut().enumerate() {
        let mut tmp_messages = vec![];
        for i in 0..total_parties - 1 {
            let msg_index = (i + 2) as usize; // 2 because first  message is for round1, second is for round 2
            tmp_messages.push(keygen.message_queue()[msg_index].clone());
        }
        p2p_msg_hashmap.insert(party_index, tmp_messages);
    }

    p2p_msg(&mut p2p_msg_hashmap, keygen_vec);

    for keygen in keygen_vec.iter_mut() {
        keygen.proceed();
    }

    for i in keygen_vec.iter_mut() {
        msgs_vec.push(i.message_queue()[(total_parties+1) as usize].clone());
    }

    broadcast_msg(&mut msgs_vec, keygen_vec);

    for keygen in keygen_vec.iter_mut() {
        keygen.proceed();
    }

    println!("keygen 1:{:?}", &keygen_vec[0]);
    println!("keygen 2:{:?}", &keygen_vec[1]);
    println!("keygen 3:{:?}", &keygen_vec[2]);
    println!("keygen 4:{:?}", &keygen_vec[3]);

    for keygen in keygen_vec.iter_mut() {
        let localkey = keygen.pick_output().unwrap().unwrap();
        println!("Public Key:{:?}",localkey.public_key());
        local_key_vec.push(localkey);
    }
}

fn run_signing(total_parties: u16, total_threshold: u16, keygen_vec: &mut Vec<Keygen>,local_key_vec: &mut Vec<LocalKey>)
{
    let mut offline_stage_vec = vec![];
    let mut s_l = vec![];
    for i in 1..=total_threshold + 1{
        s_l.push(i);
    }

    compute_offline_signing(keygen_vec, s_l.clone(), &mut offline_stage_vec, total_parties, total_threshold, local_key_vec);

    let mut offline_output_vec = vec![];

    let msg_bytes = b"hello";
    let msg_to_sign = HSha256::create_hash(&[&BigInt::from_bytes(msg_bytes)]);
    for offline_stage in &mut offline_stage_vec {
        let offline_output = offline_stage.pick_output().unwrap().unwrap();
        offline_output_vec.push(offline_output);
    }
    sign_message(msg_to_sign.clone(), &offline_output_vec);
    offline_stage_vec.clear();

    println!("==========================Another Signing===========================");
    compute_offline_signing(keygen_vec, s_l.clone(), &mut offline_stage_vec, total_parties, total_threshold, local_key_vec);

    let msg_bytes = b"there";
    let msg_to_sign = HSha256::create_hash(&[&BigInt::from_bytes(msg_bytes)]);
    sign_message(msg_to_sign.clone(), &offline_output_vec);
    offline_stage_vec.clear();

    println!("==========================Another Signing===========================");
    compute_offline_signing(keygen_vec, s_l.clone(), &mut offline_stage_vec, total_parties, total_threshold, local_key_vec);

    let msg_bytes = b"supra";
    let msg_to_sign = HSha256::create_hash(&[&BigInt::from_bytes(msg_bytes)]);
    sign_message(msg_to_sign.clone(), &offline_output_vec);
    offline_stage_vec.clear();
}

fn broadcast_msg_sign(msgs_vec: &mut Vec<Msg<OfflineProtocolMessage>>, offline_stage_vec: &mut Vec<OfflineStage>)
{
    for (k,v) in msgs_vec.iter().enumerate() {
        for (i, offline_stage) in offline_stage_vec.iter_mut().enumerate() {
            if k != i {
                offline_stage.handle_incoming(v.clone());
            }
        }
    }
}

fn p2p_msg_sign(p2p_msg_hashmap: &mut HashMap<usize ,Vec<Msg<OfflineProtocolMessage>>>, offline_stage_vec: &mut Vec<OfflineStage>)
{
    for (party_index, msg_vec) in p2p_msg_hashmap {

        for msg in msg_vec
        {
            let receiver = msg.receiver.unwrap();
            offline_stage_vec[(receiver - 1) as usize].handle_incoming(msg.clone());
        }
    }
}

fn sign_message(msg_to_sign : BigInt, offline_output_vec: &Vec<CompletedOfflineStage>)
{
    let mut manual_sign_vec = vec![];
    let mut partial_share_hashmap = HashMap::new();

    let mut party_index = 1;
    for offline_output in offline_output_vec {
        let (manual_sign, partial_share) = SignManual::new( msg_to_sign.clone(),offline_output.clone()).unwrap();
        manual_sign_vec.push(manual_sign);
        partial_share_hashmap.insert(party_index, partial_share);
        party_index += 1;
    }


    for (index, manual_sign) in manual_sign_vec.into_iter().enumerate() {
        let party_index = index +1;
        let mut partial_share_vec= vec![];
        for (p_index, partial_share) in partial_share_hashmap.iter() {
            if *p_index != party_index {
                partial_share_vec.push(partial_share.clone());
            }
        }
        let signature = manual_sign.complete(&partial_share_vec).unwrap();
        partial_share_vec.clear();
        println!("{:#?}", signature);
    }
}

fn compute_offline_signing(keygen_vec: &mut Vec<Keygen>, s_l: Vec<u16>, offline_stage_vec: &mut Vec<OfflineStage>, total_parties: u16, total_threshold: u16, local_key_vec: &mut Vec<LocalKey>)
{
    for (i, keygen) in keygen_vec.iter_mut().enumerate()
    {
        let index = keygen.party_ind();
        if index <= total_threshold + 1 {
            let local_key = local_key_vec[i].clone();
            println!("{}", i);
            let mut offline_stage=  OfflineStage::new(index, s_l.clone(), local_key).unwrap();
            println!("offline_stage: {:?}", offline_stage);
            offline_stage.proceed();
            offline_stage_vec.push( offline_stage );
        }
    }

    let mut msgs_vec = vec![];

    for offline_stage in offline_stage_vec.iter_mut() {
        println!("Offline Stage: {:?}", offline_stage);
        let msg = offline_stage.message_queue()[0].clone();
        msgs_vec.push(msg);
    }

    broadcast_msg_sign(&mut msgs_vec, offline_stage_vec );

    for offline_stage in offline_stage_vec.iter_mut() {
        offline_stage.proceed();
    }

    msgs_vec.clear();

    for offline_stage in offline_stage_vec.iter() {
        println!("Offline Stage: {:?}", offline_stage);
    }

    let mut p2p_msg_hashmap = HashMap::new();
    for (party_index,offline_stage) in offline_stage_vec.iter_mut().enumerate() {
        let mut tmp_messages = vec![];
        for i in 0..total_threshold {
            let msg_index = (i + 1) as usize; // 2 because first  message is for round1, second is for round 1
            tmp_messages.push(offline_stage.message_queue()[msg_index].clone());
        }
        p2p_msg_hashmap.insert(party_index, tmp_messages);
    }

    p2p_msg_sign(&mut p2p_msg_hashmap, offline_stage_vec);

    for offline_stage in offline_stage_vec.iter_mut() {
        offline_stage.proceed();
    }

    for offline_stage in offline_stage_vec.iter() {
        println!("Offline Stage: {:?}", offline_stage);
    }

    for offline_stage in offline_stage_vec.iter_mut() {
        println!("Offline Stage: {:?}", offline_stage);
        let msg = offline_stage.message_queue()[(total_threshold+1) as usize].clone();
        msgs_vec.push(msg);
    }

    broadcast_msg_sign(&mut msgs_vec, offline_stage_vec );

    msgs_vec.clear();

    for offline_stage in &mut offline_stage_vec.iter_mut() {
        offline_stage.proceed();
    }

    for offline_stage in offline_stage_vec.iter() {
        println!("Offline Stage: {:?}", offline_stage);
    }

    for offline_stage in offline_stage_vec.iter_mut() {
        println!("Offline Stage: {:?}", offline_stage);
        let msg = offline_stage.message_queue()[(total_threshold+2) as usize].clone();
        msgs_vec.push(msg);
    }

    broadcast_msg_sign(&mut msgs_vec, offline_stage_vec );

    msgs_vec.clear();

    for offline_stage in offline_stage_vec.iter_mut() {
        offline_stage.proceed();
    }

    for offline_stage in offline_stage_vec.iter() {
        println!("Offline Stage: {:?}", offline_stage);
    }

    for offline_stage in offline_stage_vec.iter_mut() {
        println!("Offline Stage: {:?}", offline_stage);
        let msg = offline_stage.message_queue()[(total_threshold+3) as usize].clone();
        msgs_vec.push(msg);
    }

    broadcast_msg_sign(&mut msgs_vec, offline_stage_vec );

    msgs_vec.clear();

    for offline_stage in offline_stage_vec.iter_mut() {
        offline_stage.proceed();
    }

    for offline_stage in offline_stage_vec.iter() {
        println!("Offline Stage: {:?}", offline_stage);
    }

    for offline_stage in offline_stage_vec.iter_mut() {
        println!("Offline Stage: {:?}", offline_stage);
        let msg = offline_stage.message_queue()[(total_threshold+4) as usize].clone();
        msgs_vec.push(msg);
    }

    broadcast_msg_sign(&mut msgs_vec, offline_stage_vec );

    msgs_vec.clear();

    for offline_stage in offline_stage_vec.iter_mut() {
        offline_stage.proceed();
    }

    for offline_stage in offline_stage_vec.iter() {
        println!("Offline Stage: {:?}", offline_stage);
    }
}