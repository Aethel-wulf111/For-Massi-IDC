import os, binascii, json, datetime, pefile, hashlib, string, re
from elftools.elf.elffile import ELFFile

# Dictionary mapping architecture names to numbers
ARCH_NUMBER_MAPPING = {
    'EM_NONE': 0,
    'EM_M32': 1,
    'EM_SPARC': 2,
    'EM_386': 3,
    'EM_68K': 4,
    'EM_88K': 5,
    'EM_860': 7,
    'EM_MIPS': 8,
    'EM_S370': 9,
    'EM_MIPS_RS3_LE': 10,
    'EM_PARISC': 15,
    'EM_VPP500': 17,
    'EM_SPARC32PLUS': 18,
    'EM_960': 19,
    'EM_PPC': 20,
    'EM_PPC64': 21,
    'EM_S390': 22,
    'EM_ARM': 40,
    'EM_SH': 42,
    'EM_SPARCV9': 43,
    'EM_H8_300': 46,
    'EM_IA_64': 50,
    'EM_X86_64': 62,
    'EM_AARCH64': 183,
    'EM_RISCV': 243,
}

now = datetime.datetime.now()

def get_all_files():
    all_files = []
    os.chdir('/var/www/basic-flask-app/static/uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def Calculate_size():
    return os.path.getsize(get_all_files()[0]) / (1024 * 1024)  # Conversion en mégaoctets (MB)

def strings(filename, min=4):
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

def extract_Strings_from_file (file_path):
    file_name = "strings_"+file_path.split("/")[-1].split(".")[0]+".txt"
    file = open(file_name,"w",encoding="utf-8")
    for s in strings(file_path):
        file.write(s)
        file.write("\n")
    file.close()
    print("["+str(now)+"]~ The Strings file has been created!")


def md5sum(file_path, blocksize=65536):
    hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

def hash_file_if_is_not_a_file_system(file_path):
    hash_file = md5sum(file_path)
    return {"md5Hash" : hash_file}

def find_bitcoin (pe):
    # Find the section that contains the Bitcoin address
    section = pe.sections[-1] # assume the address is in the last section
    data = section.get_data()

    # Use regular expressions to find the Bitcoin address in the data
    pattern = re.compile(b'[13][a-km-zA-HJ-NP-Z0-9]{26,33}')
    match = pattern.search(data)

    try:
        if match:
            # Convert the Bitcoin address to a binary format
            address = match.group()
            binary_address = binascii.unhexlify(hashlib.new('ripemd160', hashlib.sha256(binascii.unhexlify('00' + address)).digest()).hexdigest())
            return 1
        else:
            return 0
    except TypeError:
        return 0

def get_debug_rva(pe):
    # Get the debug directory
    debug_dir_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].VirtualAddress
    debug_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size

    # Check if the debug directory is valid
    if debug_dir_rva == 0 or debug_dir_size == 0:
        return 0
        print("No debug directory found.")
    else:
        # Get the debug directory entry
        debug_entry = pe.get_section_by_rva(debug_dir_rva)

        # Get the DebugRVA from the debug directory entry
        debug_rva = debug_entry.VirtualAddress

        #print("DebugRVA:", hex(debug_rva))
        return debug_rva

def get_IatVRA(pe):
    # Get the IAT directory
    iat_dir_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    iat_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size

    # Check if the IAT directory is valid
    if iat_dir_rva == 0 or iat_dir_size == 0:
        #print("No IAT directory found.")
        return 0
    else:
        # Get the IAT section
        iat_section = pe.get_section_by_rva(iat_dir_rva)

        # Get the IAT RVA from the section header
        iat_rva = iat_section.VirtualAddress

        #print("IAT RVA:", hex(iat_rva))
        return iat_rva

def extract_pe_info(file_path):
    with open(file_path, "rb") as file_content:
        pe= pefile.PE(data=file_content.read(), fast_load=True)
    pe.parse_data_directories()
    countf = 0
    countm = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        countf += 1
        for imp in entry.imports:
            countm += 1
    function_exp = []
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            function_exp.append(exp.name)
    except Exception as e:
        pass
    pe_information = {
        "Machine" : pe.FILE_HEADER.Machine,
        "DebugSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
        "DebugRVA" : get_debug_rva(pe),
        "MajorImageVersion" : pe.OPTIONAL_HEADER.MajorImageVersion,
        "MajorOSVersion" : pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        "ExportRVA" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
        "ExportSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
        "IatVRA": get_IatVRA(pe),
        "MajorLinkerVersion" : pe.OPTIONAL_HEADER.MajorLinkerVersion,
        "MinorLinkerVersion" : pe.OPTIONAL_HEADER.MinorLinkerVersion,
        "NumberOfSections" : pe.FILE_HEADER.NumberOfSections,
        "StackReserveSize" : pe.OPTIONAL_HEADER.SizeOfStackReserve,
        "DllCharacteristics" : pe.OPTIONAL_HEADER.DllCharacteristics,
        "ResourceSize" : pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        "BitcoinAddresses" : find_bitcoin(pe),
        "md5Hash" : md5sum(file_path)}
    file_content.close()
    return(pe_information)


def get_debug_rva_lin(elf):
    for section in elf.iter_sections():
        if section.name == '.debug_info':
            return section['sh_addr']
    return 0

def find_bitcoin_lin(elf):
    bitcoin_addresses = []
    for section in elf.iter_sections():
        if section.name == '.text':
            data = section.data()
            # Implement your logic to search for Bitcoin addresses within the section data
            # Example: Searching for addresses starting with '1' or '3'
            for i in range(len(data) - 25):
                if data[i] == 0x1 or data[i] == 0x3:
                    address = data[i:i+25].hex()
                    bitcoin_addresses.append(address)
    if len(bitcoin_addresses) > 0:
        return 1
    else: 
        return 0

def get_IatRVA_lin(elf):
    for section in elf.iter_sections():
        if section.name == b'.idata':
            return section['sh_addr']
    return 0

def extract_major_image_version(filename):
    with open(filename, 'rb') as file:
        elf = ELFFile(file)
        header = elf.header
        e_version = header['e_ident']['EI_VERSION']
        
        if e_version == 'EV_CURRENT':
            # Handle special case for "EV_CURRENT"
            major_image_version = 0
        else:
            major_image_version = int(e_version) >> 16

        return major_image_version

def extract_elf_information_lin(file_path):
    with open(file_path, 'rb') as file:
        elf = ELFFile(file)

        # Extract information
        pe = elf.header
        e_ident = pe['e_ident']
        major_os_version = e_ident[7] if len(e_ident) > 7 else 0

        information = {
            "Machine": ARCH_NUMBER_MAPPING.get(pe['e_machine'], 0),
            "DebugSize": pe['e_shnum'],  # Assuming it represents the size of the debug section
            "DebugRVA": get_debug_rva_lin(elf),
            "MajorImageVersion": extract_major_image_version(file_path),
            "MajorOSVersion": major_os_version,
            "ExportRVA": pe['e_ident'][8] if len(e_ident) > 8 else 0,
            "ExportSize": pe['e_shentsize'],  # Assuming it represents the size of the export section
            "IatRVA": get_IatRVA_lin(elf),
            "MajorLinkerVersion": pe['e_ident'][9] if len(e_ident) > 9 else 0,
            "MinorLinkerVersion": pe['e_ident'][10] if len(e_ident) > 10 else 0,
            "NumberOfSections": pe['e_shnum'],
            "StackReserveSize": pe['e_shentsize'],  # Assuming it represents the size of the stack reserve
            "DllCharacteristics": pe['e_ident'][11] if len(e_ident) > 11 else 0,
            "ResourceSize": pe['e_shentsize'],  # Assuming it represents the size of the resource section
            "BitcoinAddresses": find_bitcoin_lin(elf),
            "md5Hash": md5sum(file_path)
        }
        return information
    

def create_Json_File (dict):
    dict_to_json = json.dumps(dict,indent=4)
    # Get the current local date and time
    now = datetime.datetime.now()
    # Extract the local date (year, month, day)
    local_date = now.date()
    file_path = "data_file"+"_"+str(local_date)+".json"
    with open(file_path,"w") as f:
        f.write(dict_to_json)
    print("["+str(now)+"]~ The JSON file has been created!")

def hexdump(file_path):
    file_name = "hexdump_"+file_path.split("/")[-1].split(".")[0]+".txt"
    file = open(file_name,"w")
    with open(file_path, 'rb') as f:
        data = f.read()
        hex_str = binascii.hexlify(data).decode('utf-8')
        for i in range(0, len(hex_str), 16):
            line = hex_str[i:i+16]
            liine = [line[j:j+2] + " " for j in range(0, len(line), 2)]
            for i in liine:
                file.write(i)
            file.write("   ")
            liiine = [chr(int(line[j:j+2], 16)) if 32 <= int(line[j:j+2], 16) <= 126 else "." for j in range(0, len(line), 2)]
            for i in liiine:
                file.write(i)
            file.write("\n")
    file.close()
    print("["+str(now)+"]~ The Hexdump file has been created!")

def is_executable(file_path):
    _, ext = os.path.splitext(file_path)
    if ext in ['.exe', '.dll', '.sys','.ocx','.pdb','.map','.res','.tlb','.manifest']:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            if header == b'MZ':
                return True
    return False

def get_file_size(file_path):
    if os.path.isfile(file_path):
        return os.path.getsize(file_path) // 1024
    else:
        raise ValueError("File path is not valid.")

def Extract_informations(filename):
    files_paths = get_all_files()
    dataset = {}
    for file_path in files_paths:
        if is_executable(file_path) :
            if filename in file_path:
                try:
                    dataset.update({file_path : extract_pe_info(file_path)})
                except Exception as e:
                    pass
        elif ".elf" in file_path or ".axf" in file_path:
            dataset.update({file_path : extract_elf_information_lin(file_path)})
        else :
            dataset.update({file_path : hash_file_if_is_not_a_file_system(file_path)})
        hexdump(file_path)
        extract_Strings_from_file(file_path)
        if len(dataset) != 0:
            create_Json_File(dataset)
        hash_file = md5sum(file_path)
        file_size = get_file_size(file_path)
        extension = (file_path).split("/")[-1].split(".")[-1]
        return file_size, hash_file, extension

# Copyright 02-25-2023 ~ Boussoura Mohamed Cherif & Houanti Narimene