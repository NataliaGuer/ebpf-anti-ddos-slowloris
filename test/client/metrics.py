import csv
import os.path as path
import time
import requests
import sys

ip = None
url = None
csv_file = None
duration_seconds = 300
interval_seconds = 1

def main():

    try:
        arguments = sys.argv[1:]
        for argument in arguments:
            if argument.startswith("ip="):
                ip = argument[3:]
            if argument.startswith("file="):
                csv_file=argument[5:]
        
        if not ip and not csv_file:
            print("Fornire indirizzo ip e path del file csv")

        url = f"http://{ip}/"

        if not path.isfile(csv_file):
            print(f"file: {csv_file} not found")
            return False

        report_online = []
        total_requests = 0

        req_num = 0

        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['req_num', 'status', 'response_time'])

            start_time = time.time()

            while time.time() - start_time < duration_seconds:
                now = time.strftime("%H:%M:%S")
                total_requests +=1
                try:
                    request_start_time = time.time()
                    response = requests.get(url=url)
                    request_end_time = time.time()

                    response_time = (request_end_time - request_start_time) * 1000
                    status = "Online" if response.status_code == 200 else "Offline"

                    if status == "Online":
                        report_online.append(response_time)
                    
                    writer.writerow([req_num, status, f"{response_time:.2f}"])

                    print(f"{status}, {response_time:.2f}ms")
                except Exception as e:
                    writer.writerow([now, "Offline", 0])
                    print(f"Error: {e}")

                time.sleep(interval_seconds)
                req_num += 1
        
    except KeyboardInterrupt:
        print("Stopping")
    finally:
        avg_response_time = sum(report_online) / len(report_online)
        print(f"Report:\nNumero di richieste con status Online: {len(report_online)}\nTempo medio di risposta: {avg_response_time:.2f}ms\nNumero di richieste Offline: {total_requests - len(report_online)}")


if __name__ == "__main__":
    main()