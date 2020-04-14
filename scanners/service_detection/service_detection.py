# Kyle Westhaus
from color import pcolor
import socket

HTTP_MSG = b'GET / HTTP/1.0\r\n\r\n'

SMB_MSG = b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40" \
b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06" \
b"\x00\x00\x01\x00\x00\x81\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f" \
b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02" \
b"\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52" \
b"\x4b\x53\x20\x31\x2e\x30\x33\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f" \
b"\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x33\x2e\x30\x00" \
b"\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c\x4d\x31\x2e" \
b"\x32\x58\x30\x30\x32\x00\x02\x53\x61\x6d\x62\x61\x00\x02\x4e\x54" \
b"\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00\x02\x4e\x54\x20" \
b"\x4c\x4d\x20\x30\x2e\x31\x32\x00"

def run(ports_open):
    for target, ports in ports_open.items():
        print(f'Service Results on Host {target}')
        print(f'Port\tService')
        for port in ports:
            time.sleep(1)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                s.settimeout(2)
                s.connect((str(target), port))
            except:
                # Port wasn't actually open or socket error, no service detected
                print(f'{port}\tNo service detected')
                s.close()
                continue

            try:
                ssh_resp = s.recv(1024)
                ssh_resp = str(ssh_resp.rstrip(b'\r\n'), 'ascii')
            except:
                # No response, not SSH, run other detections
                pass
            else:
                # SSH, test response
                if 'SSH' in ssh_resp:
                    print(f'{port}\t{ssh_resp}')
                else:
                    print(f'{port}\tUnknown')
                    s.close()
                continue

            # Other detections
            try:
                s.send(HTTP_MSG)
            except:
                # Port wasn't actually open or socket error, no service detected
                print(f'{port}\tNo service detected')
                s.close()
                continue

            try:
                http_resp = s.recv(1024)
            except:
                # No response, not HTTP, run other detections
                pass
            else:
                if b'HTTP' in http_resp:
                    print(f'{port}\tHTTP')
                else:
                    print(f'{port}\tUnknown')
                    s.close()
                continue
            
            # Other detections
            try:
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                s.connect((str(target), port))
                s.send(SMB_MSG)
            except:
                # Port wasn't actually open or socket error, no service detected
                print(f'{port}\tNo service detected')
                continue

            try:
                smb_resp = s.recv(1024)
            except:
                # No response, all detections failed
                pass
            else:
                if b'SMB' in smb_resp:
                    print(f'{port}\tSamba')
                    continue
            
            # Fallthrough, all detections failed
            print(f'{port}\tUnknown')
            s.close()
    
    print('Service detection complete.')

