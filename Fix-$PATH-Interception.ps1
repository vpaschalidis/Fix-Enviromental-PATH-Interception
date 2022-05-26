$EnvPath = Get-ChildItem -Path Env:Path
$Paths = $EnvPath.Value -split ";"

    ForEach ($Index in (0..($Paths.Count - 2)))
    {   
        $acl = get-acl $Paths[$Index] | Where-Object {($_.AccessToString -match "(BUILTIN\\Users|NT AUTHORITY\\Authenticated Users) Allow  [A-Za-z,\ ]{0,}(FullControl|Modify|ChangePermissions|SetValue|TakeOwnership)[A-Za-z,\ ]{0,}\n")}

        if($acl.count -gt 0){ 

        Write-Host "======== Current Status ========"
        Write-Host ""
        Write-Host "Enviromental Path" $Paths[$Index] "is vulnerable"
        Write-Host ""
        Write-Host "====== Current Permissions ======"
        Write-Host ""
        Write-Host $acl.AccessToString
        Write-Host ""

        $rules = $acl.access | Where-Object { 
            (-not $_.IsInherited) 
        }
        ForEach($rule in $rules) {
            $acl.RemoveAccessRule($rule) | Out-Null
        }     
            Set-ACL $Paths[$Index] -AclObject $acl 
            Write-Host "======== Updated Status ========"
            Write-Host ""
            Write-Host "Enviromental Path" $Paths[$Index] "is fixed"
            Write-Host ""
            Write-Host "====== Updated Permissions ======"
            Write-Host ""
            Write-Host $acl.AccessToString
            Write-Host ""
        }
}
