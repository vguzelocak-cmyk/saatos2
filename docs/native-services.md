# I/O, registry, kriptografi ve süreç belleği

Bu servisler Windows x64 çağrı kuralıyla çalışan kullanıcı alanı
uygulamalarıdır. Gerçek Windows kernel belleği veya ring-0 yürütme
sağlamazlar. `windows_kernel_implemented` bu nedenle hâlâ `false` kalır.

## Dosya I/O

Exportlar (`ntoskrnl.exe`): `ZwCreateFile`, `ZwOpenFile`, `IoCreateFileEx`,
`ZwReadFile`, `ZwWriteFile`, `ZwFlushBuffersFile`, `ZwQueryInformationFile`,
`ZwSetInformationFile`, `ZwClose`.

- `FILE_SYNCHRONOUS_IO_NONALERT` ile senkron dosya ve dizin handle'ları
  desteklenir. Oluşturma/açma/overwrite disposition'ları 1..5 desteklenir;
  supersede, EA, security descriptor, async/APC/event I/O ve delete-on-close yoktur.
- `IoCreateFileEx` yalnızca normal dosya türü ve boş ek context ile aynı
  dosya backend'ine gider; driver create context ve device stack uygulanmadı.
- Veri erişim izinleri ve worker içindeki read/write paylaşım kuralları
  denetlenir. Başarısız paylaşım kontrolü dosyayı truncate etmez.
- Dosya konumu, explicit offset, append, EOF, byte sayısı ve flush gerçek
  POSIX dosya işlemlerine dayanır. Query sınıfları Standard=5 ve Position=14;
  Set sınıfları Position=14 ve EndOfFile=20 ile sınırlıdır.
- NT yol `\??\C:\a.bin`, özel namespace'te `files/C/a.bin` olarak saklanır.
  Dizin handle'ına göre göreli yol açılabilir. `..`, alternatif stream ve
  symlink traversal reddedilir; her dizin `openat`/`O_NOFOLLOW` ile yürünür.
- Dosya adları UTF-16'dan UTF-8'e dönüştürülür; surrogate çiftleri işlenir.
  Host dosya sistemi büyük/küçük harf davranışı korunur; NT'nin tam
  case-insensitive dosya adı semantiği ve cross-worker sharing yoktur.

Varsayılan namespace geçicidir. `--state-dir PATH` dosyaları PATH altında
korur. Sürücü bu dizindeki dosyaları desteklenen disposition'larla
değiştirebilir. Bu özellik native kodu güvenlik sandbox'ına dönüştürmez.
Dosya handle'ları Windows `FILE_OBJECT` nesneleri değildir. IRP, IOCTL,
device stack ve kernel dosya nesnesi callback'leri uygulanmamıştır.

## Volatile registry

Exportlar: `ZwCreateKey`, `ZwOpenKey`, `ZwSetValueKey`, `ZwQueryValueKey`,
`ZwDeleteValueKey`, `ZwDeleteKey`, ortak handle tablosundaki `ZwClose`.

- Worker'a özel anahtar/değer deposu kullanılır. `\Registry\Machine`,
  `\Registry\User`, Software ve System/CurrentControlSet/Services
  namespace kökleri başlatılır. Anahtarlar parent mevcutsa oluşturulur.
- Yalnızca `REG_OPTION_VOLATILE=1` ile oluşturma desteklenir. Non-volatile
  istek `STATUS_NOT_SUPPORTED` alır; `--state-dir` registry'yi kalıcı yapmaz.
- Root handle'a göre göreli açma/oluşturma, handle erişim hakları,
  create/open disposition ve silinmiş anahtar durumları denetlenir.
  Çocuk anahtar varken parent silinmez. Silinen anahtarın eski handle'ı
  değere erişemez; close işlemi yapılabilir.
- Değer tipleri ve byte payload'ları korunur. DWORD, UTF-16 metin veya
  binary veri özel bir biçime dönüştürülmeden saklanır.
- Query sınıfları ValuePartialInformation=2 ve PartialInformationAlign64=4
  desteklenir. Gerekli boyut, kısa buffer, kısmi çıktı/overflow durumları
  ayırt edilir. Diğer bilgi sınıfları ve enumeration uygulanmadı.
- İsim eşlemesinde ASCII harfler case-insensitive'dir; Unicode upcase
  tablosu, hive yükleme, link anahtarları, security descriptor ve ACL yoktur.

## CNG / OpenSSL 3

Exportlar (`cng.sys`): `BCryptOpenAlgorithmProvider`,
`BCryptCloseAlgorithmProvider`, `BCryptCreateHash`, `BCryptHashData`,
`BCryptFinishHash`, `BCryptDestroyHash`, `BCryptGetProperty`,
`BCryptImportKeyPair`, `BCryptVerifySignature`, `BCryptDestroyKey`,
`BCryptGenRandom`.

- SHA1, SHA256, SHA384, SHA512; hash provider'ında HMAC flag=8 desteklenir.
  Hash'ler streaming çalışır, finish sonrası tekrar kullanılamaz. Reusable
  hash ve kernel dispatch provider flag'leri desteklenmez.
- Hash opaque state'i OpenSSL tarafından ayrılır; `ObjectLength=0`
  raporlanır. İsteğe bağlı caller storage tutulmaz. Diğer properties:
  HashDigestLength, BlockLength, AlgorithmName ve import edilmiş key için KeyLength.
- `RSAPUBLICBLOB`/`PUBLICBLOB` RSA ve `ECCPUBLICBLOB`/`PUBLICBLOB`
  ECDSA_P256/P384/P521 public key importu vardır. Blob boyutları ve public
  key geçerliliği denetlenir; private key importu yoktur.
- RSA PKCS#1 v1.5 ve PSS doğrulaması, belirtilmiş hash algoritmasıyla
  yapılır. PSS salt uzunluğu uygulanır. ECDSA'nın Windows `r || s` imzası
  DER'e dönüştürülerek doğrulanır. Yanlış imzalar `STATUS_INVALID_SIGNATURE`
  alır; imza doğrulaması atlanmaz. PKCS#1 padding'de NULL hash-id yoktur.
- RNG, OpenSSL `RAND_bytes` kullanır. Sistem RNG flag=2 ve NULL algorithm
  veya `RNG` provider handle'ı desteklenir. Şifreleme/decryption, sertifika
  deposu ve desteklenmeyen provider'lar uygulanmadı.

OpenSSL 3 headers ve `libcrypto` gerekir. Distro paketleri README'de
belirtilmiştir. Kripto değerleri veya secret'lar loglara yazılmaz.

## MDL ve gerçek host sayfa kilitleme

Exportlar: `IoAllocateMdl`, `IoFreeMdl`, `MmBuildMdlForNonPagedPool`,
`MmProbeAndLockPages`, `MmUnlockPages`, `MmMapLockedPagesSpecifyCache`,
`MmUnmapLockedPages`.

- MDL'nin x64 ön eki, buffer offset ve byte count tutulur. IRP bağlantısı,
  secondary MDL ve quota allocation desteklenmez. MDL boyutu sınırlandırılır.
  Oluşturulmuş MDL'nin adres aralığını sonradan değiştirmek desteklenmez;
  değiştirilmiş aralık probe/map öncesinde reddedilir.
- `MmProbeAndLockPages`, kendi sürecindeki mevcut mapping'lerin izinlerini
  denetler ve sayfaları gerçekten `mlock` ile kilitler. Okuma/yazma probe'u
  ayırt edilir. Probe hatasında Windows SEH uygulanmadığından worker sonlanır.
- Aynı sayfayı kilitleyen MDL'ler için referans sayısı tutulur. Bir MDL'nin
  unlock/free işlemi diğerinin sayfasını erken açmaz. `MmUnlockPages`,
  son referansta gerçek `munlock` yapar. `RLIMIT_MEMLOCK` geçerlidir;
  kilitleme başarısızsa sahte başarı dönülmez.
- Probed MDL için cache=MmCached ve KernelMode seçimi, bu modeldeki aynı
  **süreç adresini** verir; gerçek kernel mapping'i veya ayrı fiziksel alias
  değildir. Uncached/write-combined/user mapping ve özel protection flag'leri yoktur.
- `MmBuildMdlForNonPagedPool`, host buffer'ını kilitleyip kaynak alias'ını
  kaydeder. Bu MDL için ek system mapping isteği kabul edilmez. MDL
  serbest bırakılınca bu modelin eklediği host pin referansı kaldırılır.
- PFN alanları fiziksel numara değildir; açıkça `UINTPTR_MAX` ile geçersiz
  işaretlenir. `MmGetPhysicalAddress`, `MmAllocatePagesForMdl`, DMA,
  başka süreç belleği ve Windows kernel sayfaları **uygulanmadı**.

Gerçek kernel/physical memory desteği ayrı bir kernel backend'i ve uygun
derleme/yükleme yetkisi gerektirir. Kullanıcı alanında `mlock` veya aynı
buffer'a alias vermek bu desteği sağlamaz.

## Testler

`python3 -m unittest discover -s tests -v` hem C harness'lerini hem PE
yürütmeyi çalıştırır. Bilinen SHA-256/HMAC vektörleri; RSA PKCS#1/PSS ve
ECDSA doğru/yanlış imzaları; bozuk ECC key; binary dosya round-trip,
paylaşım/erişim/traversal hataları; registry silme/erişim/buffer durumları;
MDL pin/unpin ve read-only write-probe başarısızlığı denetlenir.

`examples/make_services_driver.py` ile oluşturulan PE, 22 gerçek import
üzerinden I/O, registry, hash ve MDL servislerini çağırır. Bunların başarılı
olması Vanguard'ın çalıştığını veya Riot'un bu ortamı kabul ettiğini göstermez.
