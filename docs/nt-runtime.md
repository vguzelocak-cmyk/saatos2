# NT kullanıcı alanı uyumluluk kütüphanesi

`native/ntcompat.c`, Linux kullanıcı alanında çalışan bir işlev alt kümesidir.
PE sürücülerinin importları `driverlab_resolve` ile bu kütüphaneye bağlanır.
Sürücüden çağrılan her işlev Microsoft x64 ABI kullanır. Linux servislerine
yapılan iç çağrılar derleyici tarafından host ABI'ye dönüştürülür.

Bu bir Linux çekirdek modülü veya Windows NT çekirdeği değildir. Export
adlarının mevcut olması, tüm Windows davranışlarının veya bir sürücünün
desteklendiğini kanıtlamaz. Yetki, sistem bilgisi ve ortam kimliği
Windows'muş gibi gösterilmez. Bilinmeyen importlar yükleme hatasıdır.

## Uygulanan işlevler

Aşağıdaki isimler `ntoskrnl.exe` ve modül takma adı `ntkrnlmp.exe` üzerinden
çözülür. Sembol isimleri büyük/küçük harfe duyarlıdır; modül isimleri değildir.

| Alan | Exportlar | Uygulama |
| --- | --- | --- |
| Bellek havuzu | `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `ExFreePool` | 16 bayt hizalı host belleği, tag ve sahiplik takibi, yanlış/çift free kontrolü. Desteklenen pool türleri 0, 1, 512; sayfalar fiziksel olarak kilitlenmez ve gerçek pageable/nonpaged ayrımı yoktur. |
| UTF-16 | `RtlInitUnicodeString`, `RtlDuplicateUnicodeString`, `RtlFreeUnicodeString`, `wcslen` | Windows'un 16 bit kod birimleri ve bayt uzunlukları; kopyalama, isteğe bağlı NUL ve sahip olunan belleğin serbest bırakılması. Linux `wchar_t` kullanılmaz. |
| Bayt/dize işlemleri | `RtlCompareMemory`, `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strnlen`, `strcmp`, `strchr` | Gerçek bellek/dize işlemleri. `RtlCompareMemory`, eşleşen başlangıç baytlarının sayısını döndürür. |
| Olaylar | `KeInitializeEvent`, `KeSetEvent`, `KeResetEvent`, `KeClearEvent`, `KeReadStateEvent` | Pthread condition variable ile notification/manual-reset ve synchronization/auto-reset durumları, sinyalleme ve uyandırma. |
| Tek nesne bekleme | `KeWaitForSingleObject` | Event veya mutex; sonsuz bekleme, sıfır süreli yoklama, göreli/Windows-epoch mutlak timeout. Alertable beklemeler `STATUS_NOT_SUPPORTED` döndürür. |
| Mutex | `KeInitializeMutex`, `KeReleaseMutex` | Özyinelemeli sahiplik, başka iş parçacığına devir ve timeout. `Wait=TRUE` birleşik işlemi desteklenmez. Abandoned-mutex/thread-exit davranışı uygulanmadı. |
| Guarded mutex | `KeInitializeGuardedMutex`, `KeAcquireGuardedMutex`, `KeReleaseGuardedMutex` | Özyinelemesiz kilitleme, iş parçacığı sahipliği ve sanal special-APC disable sayacı. |
| Spinlock | `KeInitializeSpinLock`, `KeAcquireSpinLockRaiseToDpc`, `KeReleaseSpinLock`, `KeAcquireSpinLockAtDpcLevel`, `KeReleaseSpinLockFromDpcLevel` | Atomik karşılıklı dışlama ve iş parçacığına ait sanal IRQL geçişleri. Host interruptlarını kapatmaz. |
| Sanal yürütme durumu | `KeGetCurrentIrql`, `KfRaiseIrql`, `KeLowerIrql`, `KeEnterCriticalRegion`, `KeLeaveCriticalRegion`, `KeAreAllApcsDisabled` | İş parçacığına ait seviyeler/sayaçlar; geçersiz geçişler hata. Gerçek APC teslimatı veya kernel scheduler uygulanmaz. |
| Rundown | `ExInitializeRundownProtection`, `ExAcquireRundownProtection`, `ExReleaseRundownProtection`, `ExWaitForRundownProtectionRelease` | Atomik referans sayacı, yeni referanslara kapanma ve aktif referansların bitmesini bekleme. Bekleme host scheduler'a yield eder. |
| Zaman | `KeQuerySystemTimePrecise`, `KeQueryPerformanceCounter`, `KeDelayExecutionThread` | 1601 epoch/100 ns sistem zamanı, monotonic sayaç ve frekansı, göreli veya mutlak süreyle gerçek bekleme. Alertable bekleme desteklenmez. |
| Kimlik | `PsGetCurrentProcessId`, `PsGetCurrentThreadId` | Host PID/TID değerleri. Bunlar `EPROCESS`/`ETHREAD` nesnesi veya Windows handle tablosu oluşturmaz. |
| Dinamik çözümleme | `MmGetSystemRoutineAddress`, `RtlPcToFileHeader` | Yalnızca uygulanmış NT/HAL fonksiyonları ve o anda eşlenmiş sürücü adres aralığı. Bulunamayanlar NULL. |
| Fatal sürücü hatası | `KeBugCheckEx` | Kodu ve parametreleri raporlayıp worker'ı sonlandırır; Linux'a kernel panic yaptırmaz. |

`KeQueryPerformanceCounter`, ayrıca `HAL.dll` üzerinden çözülür. Toplam
50 farklı işlev ve 51 modül/sembol export kaydı vardır. Hiçbir ordinal
eşlemesi veya `cng.sys` exportu yoktur.

## Kapsam sınırları

- Dispatcher nesnelerinin host kayıtları worker ömrü boyunca tutulur.
  Sürücünün dispatcher/guarded mutex iç alanlarını doğrudan kullanmasına
  tam NT yapı uyumluluğu sağlanmaz. Meşgul nesneyi yeniden başlatmak hatadır.
- `KeSetEvent` ve `KeReleaseMutex` için `Wait=TRUE` henüz uygulanmadı ve
  worker hatasıdır. Alertable beklemeler başarı taklidi yapmaz.
- Göreli beklemeler host realtime saatinden deadline üretir; bekleme
  sırasında sistem saati değişimi NT ile tam eşdeğer davranmayabilir.
- Sanal IRQL kısıtları yalnızca bu kütüphanenin kontrol ettiği işlevlere
  uygulanır. DISPATCH_LEVEL event yoklaması desteklenir; bloklayıcı bekleme
  ve mutex beklemesi APC_LEVEL üstünde reddedilir.
- Mutex thread-exit/abandonment, wait-many, I/O/IRP/IOCTL, servis yaşam
  döngüsü, registry, kernel callback'leri, pushlock, MDL, fiziksel bellek,
  CNG, SEH/unwind ve veri exportları uygulanmadı.
- Hatalı API sözleşmeleri worker'ı sonlandırabilir. Bu çalışma yerel kod
  çalıştırır, bir güvenlik sandbox'ı değildir ve root gerektirmez.

## Doğrulama

```sh
python3 -m unittest discover -s tests -v
python3 examples/make_kernel_driver.py /tmp/driverlab-kernel-test.sys
python3 -m driverlab.run /tmp/driverlab-kernel-test.sys --execute
```

PE örneği 9 gerçek import adresini IAT üzerinden çağırır. Örneğin bir
auto-reset event üzerinde ilk yoklamanın başarı, ikinci yoklamanın timeout
döndürmesini doğrular; sabit başarı kodu yeterli olmaz. C harness ayrıca
eşzamanlı bekleyenleri, recursive mutex sahipliğini, çok iş parçacıklı
guarded mutex/spinlock sayaçlarını ve rundown kapanmasını sınar.

Bu testler Vanguard çalıştırmaz. Kullanıcının paylaştığı statik import
raporundaki 129 sembolün 43'ünün ad/modül eşlemesi bu sürümde bulunur;
bu sayı davranış uyumluluğu veya Vanguard'ın çalışabilirlik oranı değildir.
