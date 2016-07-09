extern crate chrono;
extern crate byteorder;

use std::{cmp, fs, io, mem, ptr, thread};

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use byteorder::{ReadBytesExt, LittleEndian};

use chrono::naive::datetime::NaiveDateTime;

#[repr(C)]
#[derive(Debug)]
enum MessageType {
    Connection = 0,
    Simple = 1,
    Large = 2,
    Continuation = 3,
    ContinuationEnd = 4
}

impl MessageType {
    pub fn from_u32(value: u32) -> MessageType {
        match value {
            0 => MessageType::Connection,
            1 => MessageType::Simple,
            2 => MessageType::Large,
            3 => MessageType::Continuation,
            4 => MessageType::ContinuationEnd,
            e => panic!("Unknown message type! {}", e)
        }
    }
}

#[derive(Debug)]
enum Severity {
    Info, Notice, Warn, Error, Unknown(u32)
}

impl Severity {
    pub fn from_u32(value: u32) -> Severity {
        match value {
            0 => Severity::Info,
            1 => Severity::Notice,
            2 => Severity::Warn,
            3 => Severity::Error,
            e => Severity::Unknown(e)
        }
    }
}

#[repr(C)]
struct RawConnectionMessage {
    version: u32,
    pid: u64,
    machine_name: [u8; 32],
    executable_path: [u8; 260]
}

#[repr(C)]
struct RawTextMessage {
    timestamp: u64,
    severity: u32,
    module: [u8; 32],
    channel: [u8; 32],
    message: [u8; 256]
}

enum RawMessage {
    RawConnection(RawConnectionMessage), RawText(MessageType, RawTextMessage)
}

#[derive(Debug)]
struct ConnectionMessage {
    version: u32, pid: u64, machine_name: String, executable_path: String
}

#[derive(Debug)]
struct TextMessage {
    timestamp: u64, severity: Severity, module: String, channel: String, message: String
}

#[derive(Debug)]
enum Message {
    Connection(ConnectionMessage), Text(TextMessage)
}

fn handle_client(stream: TcpStream) {
    let mut stream = stream;
    let mut version = 1u32;
    let mut pid = 0u64;

    loop {
        match read_packet(&mut stream).unwrap() {
            Message::Connection(msg) => {
                version = msg.version;
                pid = msg.pid;

                fs::create_dir_all(format!("{}", pid)).unwrap();

                println!("Connection: {:?}", msg)
            },
            Message::Text(msg) => {
                let timestamp = match version {
                    1 => NaiveDateTime::from_timestamp(msg.timestamp as i64, 0),
                    e => panic!("Version {} is unknown", e)
                };

                let mut file = fs::OpenOptions::new().write(true).create(true).append(true).open(format!("{}/{}.txt", pid, msg.module)).unwrap();

                let message = format!("{} {:?} [{}] > {}\n", timestamp.format("%F %T%.f").to_string(), msg.severity, msg.channel, msg.message);

                file.write_all(message.as_bytes()).unwrap();
            }
        }
    }
}

fn read_packet(reader: &mut Read) -> io::Result<Message> {
    let raw_packet = try!(read_raw_packet(reader));

    return match raw_packet {
        RawMessage::RawConnection(raw_message) => {
            let message = ConnectionMessage {
                version: raw_message.version,
                pid: raw_message.pid,
                machine_name: convert_string(raw_message.machine_name.to_vec()),
                executable_path: convert_string(raw_message.executable_path.to_vec())
            };

            Ok(Message::Connection(message))
        },
        RawMessage::RawText(t, raw_message) => {
            let mut message = TextMessage {
                timestamp: raw_message.timestamp,
                severity: Severity::from_u32(raw_message.severity),
                module: convert_string(raw_message.module.to_vec()),
                channel: convert_string(raw_message.channel.to_vec()),
                message: convert_string(raw_message.message.to_vec())
            };

            match t {
                MessageType::Simple => (),
                MessageType::Large => try!(read_continuation(&mut message, reader)),
                e => panic!("Message type was {:?} but not in continuation mode /o\\", e)
            }

            Ok(Message::Text(message))
        }
    };
}

fn convert_string(vector: Vec<u8>) -> String {
    let string: Vec<u8> = vector.iter().map(|x| *x).take_while(|x| *x != 0).collect();

    return String::from_utf8_lossy(&string).to_string();
}

fn read_continuation(message: &mut TextMessage, reader: &mut Read) -> io::Result<()> {
    let raw_packet = try!(read_raw_packet(reader));

    match raw_packet {
        RawMessage::RawText(MessageType::Continuation, raw_message) => {
            message.message = message.message.clone() + &convert_string(raw_message.message.to_vec());
            try!(read_continuation(message, reader));
        }
        RawMessage::RawText(MessageType::ContinuationEnd, raw_message) => {
            message.message = message.message.clone() + &convert_string(raw_message.message.to_vec());
        }
        _ => panic!("Message type was not a continuation but was in continuation mode /o\\")
    }

    return Ok(());
}

fn read_raw_packet(reader: &mut Read) -> io::Result<RawMessage> {
    let payload_size = cmp::max(mem::size_of::<RawConnectionMessage>(), mem::size_of::<RawTextMessage>());

    let message_type = MessageType::from_u32(try!(reader.read_u32::<LittleEndian>()));
    let _ = try!(reader.read_u32::<LittleEndian>()); // Padding

    let mut payload = vec![0; payload_size];
    try!(reader.read_exact(&mut payload));

    return match message_type {
        MessageType::Connection => unsafe {
            let mut message: RawConnectionMessage = mem::zeroed();

            ptr::copy_nonoverlapping(payload.as_ptr() as *const RawConnectionMessage, &mut message as *mut RawConnectionMessage, 1);

            Ok(RawMessage::RawConnection(message))
        },
        t => unsafe {
            let mut message: RawTextMessage = mem::zeroed();

            ptr::copy_nonoverlapping(payload.as_ptr() as *const RawTextMessage, &mut message as *mut RawTextMessage, 1);

            Ok(RawMessage::RawText(t, message))
        }
    };
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:3273").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move|| {
                    handle_client(stream)
                });
            }
            Err(e) => { println!("Connection failed {:?}", e) }
        }
    }

}
