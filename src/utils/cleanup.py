# src/utils/cleanup.py
import os
import shutil
import logging
import stat
from pathlib import Path
from typing import List

class DataCleaner:
    @staticmethod
    def cleanup_folders(base_path: str, folders: List[str]) -> dict:
        """Membersihkan isi folder yang ditentukan"""
        results = {}
        print(f"\nMencoba membersihkan folder di: {base_path}")

        # Cek apakah base_path ada dan bisa diakses
        if not os.path.exists(base_path):
            print(f"Membuat direktori base: {base_path}")
            try:
                os.makedirs(base_path)
            except Exception as e:
                print(f"Error membuat base directory: {e}")
                return results

        for folder in folders:
            folder_path = os.path.join(base_path, folder)
            print(f"\nProses folder: {folder_path}")
            
            try:
                if os.path.exists(folder_path):
                    print(f"Folder ditemukan: {folder_path}")
                    
                    # List semua file sebelum dihapus
                    files = os.listdir(folder_path)
                    print(f"File yang ditemukan: {len(files)}")
                    for file in files:
                        file_path = os.path.join(folder_path, file)
                        print(f"Mencoba menghapus: {file_path}")
                        try:
                            if os.path.isfile(file_path):
                                os.chmod(file_path, stat.S_IWRITE)  # Tambahkan write permission
                                os.unlink(file_path)
                                print(f"Berhasil menghapus file: {file_path}")
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path, ignore_errors=True)
                                print(f"Berhasil menghapus direktori: {file_path}")
                        except Exception as e:
                            print(f"Gagal menghapus {file_path}: {e}")

                    # Hapus folder itu sendiri
                    try:
                        shutil.rmtree(folder_path)
                        print(f"Berhasil menghapus folder: {folder_path}")
                    except Exception as e:
                        print(f"Gagal menghapus folder {folder_path}: {e}")

                # Buat folder baru
                os.makedirs(folder_path, exist_ok=True)
                print(f"Folder dibuat ulang: {folder_path}")
                
            except Exception as e:
                print(f"Error saat memproses {folder_path}: {e}")

        return results