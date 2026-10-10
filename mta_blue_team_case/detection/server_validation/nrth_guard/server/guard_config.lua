-- ===========================================================================
-- guard_config.lua — tunables for nrth_guard (MTA:SA server resource)
-- ===========================================================================
-- EVERY NUMBER HERE IS A STARTING POINT, NOT A MEASUREMENT.
-- No threshold in this file has been calibrated against the team's live server
-- in this engagement (no MTA runtime was available on the analysis host).
-- Procedure: run private_server_tests T0 (clean client, >= 30 min, N testers),
-- export `nrth_guard.db`, take p99.9 of each delta distribution, add the
-- documented margin, then flip banPolicy from "report_only".
-- ===========================================================================

GuardConfig = {}

GuardConfig.values = {
    pollMs                 = 500,   -- sample interval (server-side)
    banPolicy              = "report_only",  -- report_only | log | warn | kick

    maxHealth              = 100.0,
    maxArmor               = 100.0,
    maxMoney               = 2000000000,
    maxAmmoPerWeapon       = 500,

    healthGainPerSec       = 0.60,
    armorGainPerSec        = 12.0,
    moneyGainPerSec        = 60.0,
    ammoGainPerSec         = 40.0,

    maxTravelUnitsPerSec   = 260.0,

    -- Vehicle speed: compared in RAW game units/s of |getElementVelocity|.
    -- NO km/h conversion is asserted here because none was measured on the team's
    -- build — inventing one would produce wrong verdicts in both directions.
    maxVehicleVelocityUnits = 2.40,    -- STARTING POINT — measure p99.9 on baseline T0
    vehicleExemptModels    = {},       -- NOT FILLED: exempt ids must come from YOUR server's
                                       -- vehicle set (verify each with getElementModel). Shipping a
                                       -- guessed id list would silently disable the rule for wrong cars.

    godmodeWindowMs        = 6000,
    godmodeMinDamage       = 40.0,
    respawnMinMs           = 350,

    allowJetpack           = false,  -- set true on DM gamemodes that hand out jetpacks
    grantWindowMs          = 2500,

    scoreKickThreshold     = 12.0,
    scoreWarnThreshold     = 4.0,
    scoreDecayPerSec       = 0.02,
    sanctionCooldownMs     = 60000,
}
