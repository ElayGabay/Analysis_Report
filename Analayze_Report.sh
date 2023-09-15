#!/bin/bash

#Checking if the current user is root.
function CHECK_ROOT() {
	
	while true; 
	do
		current_user=$(whoami)
  
		if [ "$current_user" == "root" ];
		then
			break 
		else
			exit
		fi
	done
}

# Record the start time when the script starts
start_time=$(date +%s)



#Verifying if figlet is installed if not, installing figlet.
function INSTALL_FIGLET() {
if ! command -v figlet &> /dev/null; 
	then
		sudo apt-get install -y figlet &> /dev/null 
	fi
	
	#Using figlet command to display Anonymous and echo command for the color red.
	echo -e "\e[31m$(figlet Analysis :0)\e[0m"
}
function START_TIME () {
	
	echo -e ""
	echo "[*]Analysis started at: [$(date -d @$start_time '+%Y-%m-%d %H:%M:%S')]"
	echo -e ""
	
	
	
}

function DIRECTORY() {
	
   
    directory_path="Analayz_Report"

    sudo mkdir -m 777 "$directory_path"
    echo "[#]Directory $directory_path was created"
    cd "./$directory_path"
    
}



function INSTALL_APP() {
	
	
	if ! command -v strings &>/dev/null;
	then 
		echo "[@]Downloading strings...."
		sudo apt-get install -y binutils &>/dev/null
	fi
	
	if ! command -v foremost &>/dev/null;
	then 
		echo "[@]Downloading foremost...."
		sudo apt-get install -y foremost &>/dev/null
	fi
	
	
	if ! command -v bulk_extractor &>/dev/null;
	then 
		echo "[@]Downloading bulk_extractor..."
		sudo apt install -y bulk-extractor &>/dev/null
	fi
	
	
	if ! command -v binwalk &>/dev/null;
	then 
		echo "[@]Downloading binwalk...."
		sudo apt-get install -y binwalk &>/dev/null	
	fi
	
	
	if [[ -z $(sudo find / -name volatility_2.6_lin64_standalone) ]] &>/dev/null;
	then 
		echo "[@]Downloading volatility..."
		wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip &>/dev/null
		unzip -o volatility_2.6_lin64_standalone.zip &>/dev/null
		sudo chmod -R 777 volatility_2.6_lin64_standalone
		sudo chown -R "$USER" volatility_2.6_lin64_standalone
	fi
	
	if command -v strings &>/dev/null;
	then
	strings_command=$(which strings | grep -wo "strings")
	fi
	
	echo -e "" 
	echo "[*]Installed Application:"
	echo "[*]foremost ,bulk_extractor ,binwalk ,volatility ,$strings_command"
	
}


function FILE_NAME() {
	
	echo -e ""
	read -rp "[?]Spiesfile the name of the memory dump file: " file
	
	file_path=$(sudo find / -name $file 2>/dev/null | head -n1)
	
	if sudo find / -name "$file" 2>/dev/null | grep -q .
	then
		echo "[*]The memory dump $file exists: $file_path."
	else
		echo "[*]The memory dump $file dosent exists."
		exit 
	fi
	
	
}

function ANALYZE_FOREMOST() {
	
	file="$1"
    foremost_directory=$(sudo find / -type d -name Foremost_Analyze 2>/dev/null)
    
    if [ -z "$foremost_directory" ]; 
    then
        sudo mkdir Foremost_Analyze
        sudo chmod -R 777 Foremost_Analyze
        foremost_directory="./Foremost_Analyze"
        
    else
		sudo chmod -R 777 Foremost_Analyze
    fi
    
    foremost_directory=$(realpath "$foremost_directory")
    
    echo -e ""
	echo "[!]Analyzing with Foremost...."
	foremost -t all "$file" -o "$foremost_directory" &>/dev/null
	echo "[#]Analysis is done, The data is saved in: $foremost_directory"
	sudo chmod -R 777 Foremost_Analyze
}

function ANALYZE_BULK() {
	
	file="$1"
	bulk_directory=$(sudo find / -type d -name Bulk_Analyze 2>/dev/null)
	
	if [ -z "$bulk_directory" ];
	then 
		mkdir Bulk_Analyze
		bulk_directory="./Bulk_Analyze"
	fi
	
	bulk_directory=$(realpath "$bulk_directory")
	
	echo -e ""
	echo "[!]Analyzing with Bulk_extractor...."
	sudo bulk_extractor $file -o $bulk_directory &>/dev/null
	echo "[#]Analysis is done, The data is saved in: $bulk_directory"
	
	
}

function ANALYZE_BINWALK() {
	
    file="$1"
	binwalk_directory=$(sudo find / -name Binwalk_Analyze 2>/dev/null)
	
	if [ -z "$binwalk_directory" ];
	then 
		sudo mkdir Binwalk_Analyze
		binwalk_directory="./Binwalk_Analyze"
		binwalk_directory=$(realpath "$binwalk_directory")
		sudo touch "$binwalk_directory/Binwalk_Data.txt"
		sudo chmod -R 777 "$binwalk_directory"	
	fi
	
	echo -e ""
	echo "[!]Anlayziing with Binwalk...."
	binwalk --directory="$binwalk_directory" "$file" >> "$binwalk_directory/Binwalk_Data.txt" 2>/dev/null
	echo "[#]Analysis is done, The data is saved in: $binwalk_directory"
    
    
}




function ANALYZE_STRINGS() {
	
    file="$1"
    directory_strings=$(sudo find / -type d -name Strings_Analyze 2>/dev/null)


    if ! command -v strings &>/dev/null; then
        return 1
    fi

    # Create the Strings_Analyze directory if it doesn't exist
    if [ ! -d "Strings_Analyze" ]; 
    then
		directory_strings="./Strings_Analyze"
		directory_strings=$(realpath "$directory_strings")
        sudo mkdir -m 777 Strings_Analyze
    fi

    echo -e ""
    echo "[!] Analyzing with Strings...."
    strings "$file" | grep -i "password" >"Strings_Analyze/strings_password.txt"
    strings "$file" | grep -i "username" >"Strings_Analyze/strings_username.txt"
    strings "$file" | grep -i "hash" >"Strings_Analyze/strings_hash.txt"
    strings "$file" | grep -i "http" >"Strings_Analyze/strings_http.txt"
    strings "$file" | grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' >"Strings_Analyze/strings_ip_txt"
    strings "$file" | grep -E -i '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' > "Strings_Analyze/strings_mac.txt"
    strings -a "$file" | grep -i "\.exe" >"Strings_Analyze/strings_exe.txt"
    strings -a "$file" | grep -i '\\etc\\' >"Strings_Analyze/strings_etc.txt"

	
    echo "[#]Analysis is done, The data is saved in: $directory_strings"
    return 0
}

function ANALYSIS_EXIFTOOL() {
	
    file="$1"
    directory_exiftool=$(sudo find / -type d -name Exiftool_Analyze 2>/dev/null)

    if [ -z "$directory_exiftool" ]; 
    then
        sudo mkdir Exiftool_Analyze
        directory_exiftool="./Exiftool_Analyze"
        directory_exiftool=$(realpath "$directory_exiftool")
        sudo touch "$directory_exiftool/Exiftool_Data.txt"
        sudo chmod -R 777 "$directory_exiftool"
    fi

    echo -e ""
    echo "[!]Analyzing with Exiftool..."
    exiftool "$file" >> "$directory_exiftool/Exiftool_Data.txt" 2>/dev/null
    echo "[#]Analysis is done. The data is saved in: $directory_exiftool"
}


function FILE_PCAP() {
	
	file_pcap=$(sudo find / -type d -name "Analayz_Report" -exec find {} -type f -name "*.pcap" \; 2>/dev/null)
	
	if [ -n "$file_pcap" ];
    then
		echo -e ""		
		echo "[*]Network traffic data was found: $file_pcap (Size: $(ls -lh "$file_pcap" | grep -i "pcap" | awk '{print $5}'))"

	fi

}

function VOLATILITY_CHECK() {
	
    file="$1"
    
    volatility_path=$(sudo find / -type f -name volatility_2.6_lin64_standalone 2>/dev/null)
    image_profile=$("$volatility_path" 2>/dev/null -f "$file" imageinfo | grep -oP 'Suggested Profile\(s\) : \K.*$')
    image_profile_1=$("$volatility_path" 2>/dev/null -f "$file" imageinfo | awk -F ":" '/Suggested Profile\(s\) :/ {gsub(/,/, "", $2); print $2}'| awk '{print $1}')
    volatility_Data=$(sudo find / -type d -name Volatility_Data 2>/dev/null)
    
    if [ -z "$image_profile" ]; 
    then
        echo -e ""
        echo "[!]Running volatility Analysis: [Profile not Found]"
    else
        echo -e ""
        echo "[!]Running volatility Analysis: [Profile Found: $image_profile]"
        sudo mkdir -m 777 Volatility_Data
        
        # Starting the analysis of the process and saving the results in a file named "Volatility_Procsess.txt."
        echo -e ""
        echo "[!]Running volatility Analysis: Procsess"
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" pslist > Volatility_Data/Volatility_Procsess.txt 
        echo -e "\n\n" >> Volatility_Data/Volatility_Procsess.txt 
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" pstree >> Volatility_Data/Volatility_Procsess.txt 
        echo -e "\n" >> Volatility_Data/Volatility_Procsess.txt
        echo "$(date '+[%Y-%m-%d %H:%M:%S]')" >> Volatility_Data/Volatility_Procsess.txt 

        # Starting the analysis of the registry and saving the results in a file named "Volatility_Network.txt."
        echo "[!]Running volatility Analysis: Network"
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" connections > Volatility_Data/Volatility_Network.txt
        echo -e "\n\n" >> Volatility_Data/Volatility_Network.txt 
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" connscan >> Volatility_Data/Volatility_Network.txt
        echo -e "\n\n" >> Volatility_Data/Volatility_Network.txt
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" sockets >> Volatility_Data/Volatility_Network.txt
        echo -e "\n\n" >> Volatility_Data/Volatility_Network.txt
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" sockscan >> Volatility_Data/Volatility_Network.txt 
        echo -e "\n\n" >> Volatility_Data/Volatility_Network.txt 
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" netscan >> Volatility_Data/Volatility_Network.txt 
        echo -e "\n" >> Volatility_Data/Volatility_Network.txt 

        echo "[!]Running volatility Analysis: Registry"
        sudo "$volatility_path" 2>/dev/null -f "$file" --profile="$image_profile_1" dumpregistry --dump-dir=Volatility_Data &>/dev/null
    fi
}



function RESULTS() {
	
    file="$1"

    Analayz_directory=$(sudo find / -type d -name Analayz_Report 2>/dev/null)
    basename_Analayz_directory=$(basename "$Analayz_directory")
    extracted_files=0
    Bulk_directory=$(sudo find / -type d -name Bulk_Analyze 2>/dev/null)
    extracted_bulk_files=0
    Foremost_directory=$(sudo find / -type d -name Foremost_Analyze 2>/dev/null)
    extracted_foremost_files=0
    Volatility_Data_path=$(sudo find / -type d -name "Volatility_Data" 2>/dev/null)
    extracted_Volatility_files=0
    directory_Strings=$(sudo find / -type d -name Strings_Analyze 2>/dev/null)
    extracted_Strings_files=0
    file_pcap=$(sudo find / -type d -name "Analayz_Report" -exec find {} -type f -name "*.pcap" \; 2>/dev/null)
    basename_file_pcap=$(basename "$file_pcap")
    basename_file=$(basename "$file")

    if [ -n "$Analayz_directory" ]; then
        extracted_files=$(sudo find "$Analayz_directory" -type f | wc -l)
    fi

    if [ -n "$Bulk_directory" ]; then
        extracted_bulk_files=$(sudo find "$Bulk_directory" -type f | wc -l)
    fi

    if [ -n "$Foremost_directory" ]; then
        extracted_foremost_files=$(sudo find "$Foremost_directory" -type f | wc -l)
    fi

    if [ -n "$Volatility_Data_path" ]; then
        extracted_Volatility_files=$(sudo find "$Volatility_Data_path" -type f | wc -l)
    fi

    if [ -n "$directory_Strings" ]; then
        extracted_Strings_files=$(sudo find "$directory_Strings" -type f | wc -l)
    fi

    echo -e "\n\n"

    echo "[*]$(date) --> Forensics Analysis $basename_file"
    echo "[*]Saved in directory: [$basename_Analayz_directory] [Extracted files: $extracted_files]"
    echo "[*][Bulk: $extracted_bulk_files Files] [Foremost: $extracted_foremost_files Files] [Volatility: $extracted_Volatility_files Files] [Strings: $extracted_Strings_files Files] [Network: $basename_file_pcap]"
}


function REMOVE_VOL () {
	
	vol_zip=$(sudo find / -type d -name volatility_2.6_lin64_standalone 2>/dev/null)
	vol_unzip=$(sudo find / -name volatility_2.6_lin64_standalone.zip 2>/dev/null)
	
	
	sudo rm -r "$vol_zip"
	sudo rm -r "$vol_unzip"
	
	
	
}


function ZIP() {
	
    Counter=1
    local directory_path=$(sudo find / -type d -name "Analayz_Report" 2>/dev/null)
    local zip_name="Analysis_Complet_$Counter.zip"

    while [ -f "$directory_path/$zip_name" ]; 
    do
        ((Counter++))
        zip_name="Analysis_Complet_$Counter.zip"
    done
	   
    cd "$directory_path" && cd .. && sudo zip -r "$zip_name" Analayz_Report &>/dev/null && sudo rm -r Analayz_Report
	
	echo -e ""
    echo "[#]Forensics Analysis Completed [$zip_name]"
}


# Function to display the elapsed time
function DISPLAY_ELAPSED_TIME() {
    end_time=$(date +%s)
    elapsed_seconds=$((end_time - start_time))
    elapsed_minutes=$((elapsed_seconds / 60))
    elapsed_seconds=$((elapsed_seconds % 60))

    echo "[*]Script finished at: [$(date -d @$end_time '+%Y-%m-%d %H:%M:%S')]"
    echo "[*]Analysis lated time: [${elapsed_minutes}m ${elapsed_seconds}s]"
}







CHECK_ROOT
INSTALL_FIGLET "$file_path"
START_TIME "$file_path"
DIRECTORY "$file_path"
INSTALL_APP "$file_path"
FILE_NAME  "$file_path"
ANALYZE_FOREMOST "$file_path"
ANALYZE_BULK "$file_path"
ANALYZE_BINWALK "$file_path"
ANALYZE_STRINGS "$file_path"
ANALYSIS_EXIFTOOL "$file_path"
FILE_PCAP "$file_path"
VOLATILITY_CHECK "$file_path"
RESULTS "$file_path"
REMOVE_VOL  "$file_path"
ZIP  "$file_path"
DISPLAY_ELAPSED_TIME  "$file_path"
