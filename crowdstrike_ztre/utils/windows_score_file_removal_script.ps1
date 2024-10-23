# Windows Score file removal script.

# Define the list of files to check
$files = @(
    'crwd_zta_1_25.txt',
    'crwd_zta_26_50.txt',
    'crwd_zta_51_75.txt',
    'crwd_zta_76_100.txt'
)

# Iterate over each file and delete it if it exists
foreach ($file in $files) {
    
    if (Test-Path $file) {
        Remove-Item $file -Force
        # Print statement for file deletion using echo
        echo "Deleted $file"
    } else {
        # Print statement when file does not exist using echo
        echo "File $file does not exist."
    }
}