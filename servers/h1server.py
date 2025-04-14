import socket
import time
import os

def start_echo_server(host="127.0.0.1", port=8080):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Echo server running on http://{host}:{port}")
        
        try:
            while True:
                client_socket, client_address = server_socket.accept()
                with client_socket:
                    request_data = receive_full_request(client_socket)

                    if request_data is None:
                        continue

                    headers, body = parse_data(request_data)

                    write_to_file(headers, body)

                    print(f"Connection from {client_address} with ID: " \
                          f"{headers.get(b'smuggling-id')}")
                    
                    # Construct HTTP response with the request data as the body
                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        f"Content-Length: {len(request_data)}\r\n"
                        "Content-Type: text/plain\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode() + request_data
                    
                    client_socket.sendall(response)
        except KeyboardInterrupt:
            print("\nServer is shutting down...")

def receive_full_request(client_socket):
    BUFFER_SIZE = 4096
    data = b''
    while True:
        try:
            part = client_socket.recv(BUFFER_SIZE)
        except ConnectionResetError:
            return None
        except Exception as e:
            print(f"Exception: {type(e)}")
            exit(-1)
        data += part
        # Check if headers are fully received
        if b'\r\n\r\n' in data:
            headers_end = data.find(b'\r\n\r\n') + 4
            headers = data[:headers_end]
            body_start = headers_end
            # Check for Content-Length to read the full body
            content_length = 0
            for line in headers.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):
                    content_length = int(line.split(b':')[1].strip())
                    break
            if len(data[body_start:]) >= content_length:
                break
        if not part:
            break
    return data

def parse_data(recv_data: bytes):
    headers = {}

    print(recv_data)

    header, body = recv_data.split(b'\r\n\r\n', 1)

    print(f"Body: {body}")

    if recv_data.count(b'\r\n\r\n') != 1:
        print("ALERT: Unusualt amout of \\r\\n in recv_data:")
        print(recv_data)

    lines = header.split(b'\r\n')
    
    if lines[0].count(b' ') == 2:
        method, path, version = lines[0].split(b' ')
        headers[b'req-mthd'] = method
        headers[b'req-pth'] = path
        headers[b'req-vrsn'] = version
    else:
        print(f"ALERT: Server received a malformed request line: {lines[0]}")
        headers[b'Malformed-Request-Line'] = lines[0]
    # Parse headers
    for line in lines[1:]:
        # Stop processing when we hit an empty line (end of headers)
        if not line:
            break
        
        if b': ' in line:
            name, value = line.split(b': ', 1)
            # Some proxies make smuggling-id to Smuggling-Id
            if name.decode('utf-8').lower() == "smuggling-id":
                headers[b'smuggling-id'] = value
            else:
                headers[name.strip()] = value.strip()
    
    if headers.get(b'smuggling-id') is None:
        headers[b'smuggling-id'] = b'None'

    return headers, body

def write_to_file(headers: dict, body: bytes) -> None:
    req_id = b'####REQ_ID_' + headers.get(b'smuggling-id') + b'####'
    h_name = b'####H_NAME####'
    h_value = b'####H_VALUE####'
    body_signal = b'####BODY####'
    req_end = b'####REQ_END####'
    content = req_id
    for name, value in headers.items():
        content += h_name + name + h_value + value
    content += body_signal + body + req_end
    f = open("request", "wb")
    f.write(content)
    f.close()

if __name__ == "__main__":
    if not os.getcwd().endswith("servers"):
        print("Server must run in cwd /servers")
        exit(-1)
    if os.path.exists("request"):
        os.remove("request")
    start_echo_server()