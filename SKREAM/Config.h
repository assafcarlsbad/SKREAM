#pragma once

//
// Params for enabling/disabling specific mitigations.
//

#define USE_POOL_BLOATER_MITIGATION         (0)
#define USE_POOL_SLIDER_MITIGATION          (1)
#define USE_TYPE_INDEX_OVERWRITE_MITIGATION (1)

//
// Params for the PoolBloater mitigation.
//

#define MIN_POOL_CHUNKS_TO_ADD  (1)
#define MAX_POOL_CHUNKS_TO_ADD  (5)

//
// Normally we only wish to hook drivers which are not an integral part of the OS so as not to anger PatchGuard.
//

#define MAX_SIGNING_LEVEL_TO_HOOK   (SE_SIGNING_LEVEL_MICROSOFT)
