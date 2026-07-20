from onedep_lib.enums import Country, EMSubType, ExperimentType, FileType


def test_experiment_types_have_expected_values():
    assert ExperimentType.XRAY.value == "xray"
    assert ExperimentType.EM.value == "em"
    assert ExperimentType.NMR.value == "nmr"


def test_file_types_have_expected_values():
    assert FileType.MMCIF_COORD.value == "co-cif"
    assert FileType.EM_MAP.value == "vo-map"
    assert FileType.EM_HALF_MAP.value == "half-map"


def test_em_subtypes_have_expected_values():
    assert EMSubType.SPA.value == "single"
    assert EMSubType.HELICAL.value == "helical"


def test_country_usa():
    assert Country.USA.value == "United States"


def test_country_values_match_server_accepted_list():
    # The deposit server's country list is ASCII-only (lowercased), so these
    # values must not contain accented characters.
    assert Country.CURACAO.value == "Curacao"
    assert Country.IVORY_COAST.value == "Cote D'Ivoire"
    assert Country.REUNION.value == "Reunion"
    assert Country.SAINT_BARTHELEMY.value == "Saint Barthelemy"
