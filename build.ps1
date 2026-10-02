# ============================================================================
# AuditAI build script (Windows PowerShell)
# ============================================================================
#   .\build.ps1               Online build (first run: downloads missing deps)
#   .\build.ps1 -Offline      Offline build (mvn -o, works once deps are cached)
#   .\build.ps1 -JdkPath ...  Override the auto-detected JDK
#   .\build.ps1 -MvnPath ...  Override the auto-detected mvn.cmd
#
# Every machine installs the JDK and Maven somewhere different, so both are
# located at run time: candidates are tried in order, the first usable one wins.
#   JDK    -JdkPath > $env:JAVA_HOME > java on PATH > standard install dirs
#   Maven  -MvnPath > $env:MAVEN_HOME > mvn.cmd on PATH > standard install dirs
#
# A JDK must expose javac and report major >= 17; pom.xml pins release=17 to
# match the Montoya API requirement.
# ============================================================================
param([switch]$Offline, [string]$JdkPath, [string]$MvnPath)

$ErrorActionPreference = 'Stop'
$RequiredJava = 17

# Major version from `java -version`; 0 when it cannot be read.
function Get-JavaMajor([string]$javaExe) {
    # `java -version` writes to stderr, which trips ErrorActionPreference='Stop'.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $raw = (& $javaExe '-version' 2>&1) -join ' ' }
    catch { return 0 }
    finally { $ErrorActionPreference = $prev }
    $m = [regex]::Match($raw, 'version "(\d+)(?:\.(\d+))?')
    if (-not $m.Success) { return 0 }
    if ($m.Groups[1].Value -eq '1') { return [int]$m.Groups[2].Value }   # 1.8.0_x -> 8
    return [int]$m.Groups[1].Value
}

# First candidate the probe accepts, or $null. A throwing probe counts as
# "unusable" so one bad path cannot abort the whole lookup.
function Select-FirstUsable($candidates, [scriptblock]$probe) {
    foreach ($c in $candidates) {
        if (-not $c) { continue }
        try { if (& $probe $c) { return $c } } catch { }
    }
    return $null
}

# Directories the usual Windows installers put a JDK in. Globbed, so the
# version number in the folder name does not matter.
$jdkRoots = @(
    'C:\Program Files\Java', 'C:\Program Files\Eclipse Adoptium', 'C:\Program Files\Microsoft',
    'C:\Program Files\Zulu', 'C:\Program Files\Amazon Corretto', 'C:\Program Files\BellSoft',
    "$env:LOCALAPPDATA\Programs\Eclipse Adoptium", "$env:USERPROFILE\.jdks",
    "$env:USERPROFILE\scoop\apps\openjdk", "$env:USERPROFILE\scoop\apps\jdk",
    ${env:ProgramFiles}   # catches e.g. C:\Program Files\apache-maven-3.9.6, jdk-17
)

$jdkCandidates = @($JdkPath, $env:JAVA_HOME)
if ($onPath = Get-Command java.exe -ErrorAction SilentlyContinue) {
    $jdkCandidates += Split-Path -Parent (Split-Path -Parent $onPath.Source)  # ...\bin\java.exe -> home
}
foreach ($root in $jdkRoots) {
    if (Test-Path $root) {
        $jdkCandidates += Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | ForEach-Object FullName
    }
}

$jdkProbe = {
    param($dir)
    (Test-Path "$dir\bin\javac.exe") -and ((Get-JavaMajor "$dir\bin\java.exe") -ge $RequiredJava)
}
$jdk = Select-FirstUsable $jdkCandidates $jdkProbe
if (-not $jdk) {
    throw "[build] No JDK $RequiredJava+ found. Set JAVA_HOME, add java to PATH, or run .\build.ps1 -JdkPath <path-to-jdk>."
}
if ($JdkPath -and $jdk -ne $JdkPath) {
    throw "[build] -JdkPath '$JdkPath' is not a usable JDK $RequiredJava+; refusing to silently build with '$jdk'."
}
$env:JAVA_HOME = $jdk
$env:Path = "$jdk\bin;$env:Path"
Write-Host "[build] JDK: $jdk (major $(Get-JavaMajor "$jdk\bin\java.exe"))"

$mvnCandidates = @($MvnPath)
if ($env:MAVEN_HOME) { $mvnCandidates += "$env:MAVEN_HOME\bin\mvn.cmd" }
foreach ($name in 'mvn.cmd', 'mvn') {
    if ($onPath = Get-Command $name -ErrorAction SilentlyContinue) { $mvnCandidates += $onPath.Source }
}
foreach ($root in @('C:\Program Files\Apache', 'C:\ProgramData\chocolatey',
        "$env:USERPROFILE\scoop\apps\maven\current", ${env:ProgramFiles})) {
    if (Test-Path $root) {
        $mvnCandidates += "$root\bin\mvn.cmd"
        $mvnCandidates += Get-ChildItem $root -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { "$($_.FullName)\bin\mvn.cmd" }
    }
}

$mvn = Select-FirstUsable $mvnCandidates { param($p) Test-Path $p }
if (-not $mvn) {
    throw "[build] mvn.cmd not found. Install Maven 3.9+, set MAVEN_HOME, or run .\build.ps1 -MvnPath <path-to-mvn.cmd>."
}
Write-Host "[build] Maven: $mvn"

# Always run from the project root, regardless of the caller's directory.
Set-Location $PSScriptRoot

if ($Offline) {
    Write-Host '[build] Offline mode: local Maven repository only (fails if deps are not cached)'
    & $mvn -o clean package
} else {
    Write-Host '[build] Online mode: first build downloads missing deps to the local Maven repository'
    & $mvn clean package
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[build] Build failed, exit code: $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Project version from pom.xml (first <version>, to avoid the `#` comment pitfall
# inside PowerShell double quotes).
$pomVersion = (Select-String -Path .\pom.xml -Pattern '<version>([^<]+)</version>' |
                 Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $pomVersion) {
    throw '[build] Could not parse <version> from pom.xml; check that pom.xml is intact.'
}
Write-Host "[build] Build succeeded: target\burp-audit-ai-$pomVersion.jar"
