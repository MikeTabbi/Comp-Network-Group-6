import os

def chunk_file(file_path, chunk_size=1024):
    chunks = []
    with open(file_path, 'rb') as f:
        chunk_num = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunk_filename = f"{file_path}_chunk_{chunk_num}"
            with open(chunk_filename, 'wb') as chunk_file:
                chunk_file.write(chunk)
            chunks.append(chunk_filename)
            chunk_num += 1
    return chunks
