function Get-EncryptedPassword
{
    [cmdeltbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$secret,

        [Parameter(Mandatory = $true)]
        [string]$bucket,

        [Parameter(Mandatory = $true)]
        [string]$s3FilePath,

        [Parameter(Mandatory = $true)]
        [string]$tempFilePath = "$env:temp\tempsecs.json",

        [Parameter(Mandatory = $true)]
        [string]$bucketRegion
    )

    #determine if the file in s3 matches local temp file if not download  a new s3 file.
    $downloadFile = $false

    if (Test-Path $tempFilePath)
    {
        try
        {
            $s3file = Get-S3Object -BucketName $bucket -Key $s3FilePath -Region $bucketRegion -ErrorAction Stop

            if ( !$s3file ) { throw "$s3FilePath does not exist.  Can't retrieve encrypted passwords." }
        }
        catch
        {
            throw $_.exception.message
        }

        #get and compare hashes for s3 vs. local file. download if hashes do not match.
        $tempFileMD5 = ( Get-FileHash $tempFilePath -Algorithm MD5 ).hash.tolower()

        $s3MD5 = $s3file.etag.replace('"', '').tolower()

        if ($tempFileMD5 -ne $s3MD5) { $downloadFile = $true }

    }
    else
    {
        $downloadFile = $true
    }

    #if download is true get the encrypted passwords json from s3.
    if ($downloadFile)
    {
        $VerbosePreference = 'Continue'
        Write-Verbose "Local config out of date, pulling encypted passwords from S3 - $s3FilePath."
        $VerbosePreference = 'SilentlyContinue'
        #Import the JSON file from S3
        try
        {
            #Get File Properties
            Read-S3Object -BucketName $bucket -Key $s3FilePath -File $tempFilePath -Region $bucketRegion -ErrorAction Stop | Out-Null
        }
        catch
        {
            throw $_.exception.message

        }
    }

    #read json encryption list file and convert to powershell objects.
    $encryptionList = Get-Content -Raw $tempFilePath | ConvertFrom-Json

    #Loop through and find the block associated with the parameter for secret (Fail if no match)
    if ( $encryptionList.name -notcontains $secret )
    {
        throw "The file at $s3FilePath does not contain password with the key - $secret."
    }

    #pull decrypted password out of file.
    $encryptedPassword = ( $encryptionList |  Where-Object { $_.name -eq $secret } ).details.password

    if ($encryptedPassword.count -ne 1) { throw "$($encryptedPassword.count) passwords returned != 1.  Make sure that more than one password isn't defined for $secret." }

    #Decrypt the Password
    $decryptedPassword = Invoke-KMSDecryptText $encryptedPassword 'us-east-1'

    #Send it back to the calling script
    return $decryptedPassword
}

