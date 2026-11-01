# NT uzantıları ve sınırları

Bu katman 23 işlev ve bir veri exportu ekler. Tüm runtime'da 108 export kaydı
vardır; bunlardan biri `KeNumberProcessors` veri adresidir. Bu sayı Windows
çekirdeğinin tamamının veya Vanguard'ın desteklendiğini göstermez.

## Secure CRT ve Unicode

- `strcpy_s`, `strncpy_s`, `wcscpy_s`, `wcscat_s`: kapasite, NUL, overlap
  ve hata kontrolleri. Wide karakterler Windows gibi 16 bittir.
  `_TRUNCATE=SIZE_MAX`, `strncpy_s` için kesilince `STRUNCATE=80` döndürür.
  Geçersiz argüman/range hatası EINVAL/ERANGE alır; uygun destination varsa
  ilk birim NUL yapılır. Windows invalid-parameter-handler altyapısı yoktur.
- `RtlPrefixUnicodeString`: uzunlukla sınırlı UTF-16 prefix karşılaştırma.
  Case-insensitive eşleme host `C.UTF-8` basit Unicode uppercase tablosunu
  kullanır; Windows NLS tablosuyla tüm sürümlerde eşdeğerlik garanti edilmez.
  Surrogate çiftleri case-fold edilmez. Locale yoksa ASCII desteklenir,
  non-ASCII case-fold isteği worker hatasıdır.
- `RtlMultiByteToUnicodeN`: bu runtime'ın sabit **Windows-1252** ANSI
  tablosunu kullanır. UTF-8 dönüştürücüsü değildir ve host locale'ini ANSI
  code page olarak kullanmaz. Output byte kapasitesine sığan tam UTF-16
  birimler yazılır; yazılan byte sayısı döndürülür. ANSI code page seçimi
  veya Windows NLS yükleme henüz yoktur.

## Pushlock ve rundown

`ExInitializePushLock`, `ExAcquirePushLockExclusiveEx`,
`ExReleasePushLockExclusiveEx`, `ExAcquirePushLockSharedEx`,
`ExReleasePushLockSharedEx` gerçek pthread okuyucu/yazıcı kilidi kullanır.
Birden çok okuyucu eşzamanlı girebilir; yazıcı karşılıklı dışlanır. Sahiplik,
recursive acquire ve meşgul kilidin yeniden başlatılması denetlenir.

Acquire/release için flags=0, sanal IRQL <= APC_LEVEL ve normal kernel
APC'lerinin sanal olarak devre dışı olması gerekir. `KeEnterCriticalRegion`
ve sonrasında `KeLeaveCriticalRegion` bunu sağlar. Mutex sahipliğinde de
normal-APC disable sayacı tutulur; recursive sahiplikte son release ile açılır.
Gerçek Windows APC teslimatı yoktur. Sürücünün pushlock alanını kendi inline
fast-path atomikleriyle değiştirip host kilitlerini atlaması desteklenmez.

`ExAllocateCacheAwareRundownProtection`, `ExFreeCacheAwareRundownProtection`,
`ExAcquireRundownProtectionCacheAwareEx`, `ExReleaseRundownProtectionCacheAwareEx`,
`ExWaitForRundownProtectionReleaseCacheAware`: birden çok referansla acquire,
yeni referanslara kapanma ve mevcut referansların bitmesini bekleme.
Allocation 64 byte hizalıdır; gerçek NT per-CPU cache-aware yerleşimi yerine
tek mutex/condition ve sayaç kullanılır. Fiziksel nonpaged pool sağlanmaz.
Aktif referans veya bekleyen varken free hatadır. Count=0 desteklenmez.

## Zaman ve işlemciler

`RtlTimeToTimeFields`, 1601 epoch ve 100 ns tick değerlerini UTC Gregoryen
takvim alanlarına çevirir; artık yıl ve negatif tick kesirleri işlenir.
`ExSystemTimeToLocalTime`, belirtilen an için host timezone/DST offset'ini
uygular. Windows registry timezone verisi kullanılmaz.

`KeQueryActiveProcessorCountEx`, worker açılırken erişilebilir olan Linux
CPU affinity kümesinin snapshot'ını kullanır. Bu CPU'lar host CPU numarasına
göre sıralanıp runtime içinde 64 üyeli gruplar olarak numaralanır. Group
0xffff tüm grupları sayar. `KeGetCurrentProcessorNumberEx`, o anki host CPU'yu
bu namespace'e eşler; grup ve grup içi numarayı verir. Runtime dışından
affinity'nin snapshot dışına genişletilmesi desteklenmez.

`KeNumberProcessors` bir fonksiyon değildir: ilk runtime grubundaki aktif
CPU sayısını tutan byte'ın adresi IAT'ye yazılır. Veri importunun kod adresi
gibi çağrılması doğru değildir. Tam HAL/topoloji, CPU hotplug ve IPI yoktur.

## Probe ve stack

`ProbeForRead`/`ProbeForWrite`, uzunluk/taşma/hizalama ve süreç mapping
izinlerini denetler. Sıfır uzunlukta probe yapılmaz. Alignment 1/2/4/8/16
desteklenir. Bu kontrol bir mapping snapshot'ıdır; sonradan unmap/protect
edilmesine karşı garanti vermez ve sayfaları kilitlemez. Hatalarda Windows
SEH uygulanmadığından worker açık bir hata mesajıyla sonlanır.

`__chkstk`, x64 assembly ile caller'ın olası stack alanını 4 KiB aralıklarla
gerçekten okur; RAX/RCX korunur. Allocation miktarı RAX'tan alınır; routine
RSP allocation'ını caller yerine yapmaz. Linux stack/guard davranışı
kullanılır; Windows guard exception/SEH/unwind altyapısı eklenmiş değildir.

## Testler ve kullanım

```sh
python3 -m unittest discover -s tests -v
python3 examples/make_kernel_driver.py --extensions /tmp/driverlab-extras-test.sys
python3 -m driverlab.run /tmp/driverlab-extras-test.sys --execute
```

Genişletilmiş PE 17 import üzerinden stack probe, pushlock, secure string
copy ve veri importunu da sınar. C testleri paralel okuyucuları, contended
yazıcıları, sayılı rundown beklemesini, CPU affinity eşlemesini, tarih/DST,
ANSI/UTF-16 sınırlarını ve probe hatalarını doğrular. Ayrı guard-page testi
stack probe'un yalnızca geri dönen boş bir işlev olmadığını denetler.

Bu değişiklikler APC/DPC, timer scheduler, system thread, work-item,
Windows nesne yöneticisi, `__C_specific_handler`, kernel bugcheck callback
altyapısı veya fiziksel sayfa allocator'ı eklemez. Bu alanlardaki bilinmeyen
importlar hâlâ sürücü giriş fonksiyonu çağrılmadan hata verir.
