DEFINITIONS = deye_sg04lp3 deye_hybrid deye_sg03lp1_eu

DOWNLOAD_TARGETS = $(addprefix download-, $(DEFINITIONS))
IMPORT_TARGETS = $(addprefix import-, $(DEFINITIONS))

HA_DEFINITIONS_URL="https://raw.githubusercontent.com/adnovea/solarman_lse/e8df33d6b91c37fb3b5f7bb0d25ebdcf4e571eb4/custom_components/solarman_lse/inverter_definitions/"


$(DOWNLOAD_TARGETS): download-%:
	wget -q $(HA_DEFINITIONS_URL)/$*.yaml -O $*_ha.yaml

$(IMPORT_TARGETS): import-%:
	python ../tools/ha_definition_import.py \
		--definition-code $* \
		--sensors-file ../src/deye_sensors_$*.py