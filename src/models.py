from dataclasses import dataclass

@dataclass
class Event:

    timestamp : str
    event_type : str
    username : str
    source_ip : str 
    severity : str
    raw_log : str 
