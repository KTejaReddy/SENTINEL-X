from .dast import DastAdapter
from .lab_range import LabRangeAdapter
from .nmap import NmapAdapter
from .nuclei import NucleiAdapter
from .scanners import GitleaksAdapter, SemgrepAdapter, TrivyAdapter, ZapAdapter
from .ingest import SuricataAdapter, WazuhAdapter, ZeekAdapter


def register_all(registry) -> None:
    for adapter in [
        NmapAdapter(),
        NucleiAdapter(),
        ZapAdapter(),
        SemgrepAdapter(),
        GitleaksAdapter(),
        TrivyAdapter(),
        SuricataAdapter(),
        ZeekAdapter(),
        WazuhAdapter(),
        LabRangeAdapter(),
        DastAdapter(),
    ]:
        registry.register(adapter)
