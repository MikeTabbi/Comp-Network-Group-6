import requests
import os


def download_chunks(chunk_names, peers, save_dir="downloads"):
    os.makedirs(save_dir, exist_ok=True)
    for chunk_name in chunk_names:
        for peer in peers:
            try:
                url = f"http://{peer}/get_chunk?name={chunk_name}"
                response = requests.get(url)
                if response.status_code == 200:
                    with open(os.path.join(save_dir, chunk_name), 'wb') as f:
                        f.write(response.content)
                    print(f"Downloaded {chunk_name} from {peer}")
                    break
            except Exception as e:
                print(f"Error from {peer}: {e}")
        else:
            print(f"Failed to download {chunk_name} from any peer")

def merge_chunks(chunk_dir, output_file):
    with open(output_file, 'wb') as outfile:
        for chunk_name in sorted(os.listdir(chunk_dir)):
            chunk_path = os.path.join(chunk_dir, chunk_name)
            with open(chunk_path, 'rb') as infile:
                outfile.write(infile.read())
    print(f"File reconstructed as {output_file}")
