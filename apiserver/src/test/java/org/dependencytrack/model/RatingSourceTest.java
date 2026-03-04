/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link RatingSource} precedence and overwrite logic.
 */
class RatingSourceTest {

    @Test
    void testPrecedenceOrder() {
        // Verify precedence values are correctly ordered
        assertTrue(RatingSource.MANUAL.getPrecedence() > RatingSource.VEX.getPrecedence());
        assertTrue(RatingSource.VEX.getPrecedence() > RatingSource.POLICY.getPrecedence());
        assertTrue(RatingSource.POLICY.getPrecedence() > RatingSource.NVD.getPrecedence());
    }

    @Test
    void testCanOverwrite_ManualOverwritesAll() {
        // MANUAL should be able to overwrite everything, including itself
        assertTrue(RatingSource.MANUAL.canOverwrite(RatingSource.MANUAL));
        assertTrue(RatingSource.MANUAL.canOverwrite(RatingSource.VEX));
        assertTrue(RatingSource.MANUAL.canOverwrite(RatingSource.POLICY));
        assertTrue(RatingSource.MANUAL.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.MANUAL.canOverwrite(null));
    }

    @Test
    void testCanOverwrite_VexOverwritesPolicyAndNvd() {
        // VEX should be able to overwrite itself, POLICY, and NVD
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.VEX));
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.POLICY));
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.VEX.canOverwrite(null));

        // VEX should NOT be able to overwrite MANUAL
        assertFalse(RatingSource.VEX.canOverwrite(RatingSource.MANUAL));
    }

    @Test
    void testCanOverwrite_PolicyOverwritesNvd() {
        // POLICY should be able to overwrite itself and NVD
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.POLICY));
        assertTrue(RatingSource.POLICY.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.POLICY.canOverwrite(null));

        // POLICY should NOT be able to overwrite MANUAL or VEX
        assertFalse(RatingSource.POLICY.canOverwrite(RatingSource.MANUAL));
        assertFalse(RatingSource.POLICY.canOverwrite(RatingSource.VEX));
    }

    @Test
    void testCanOverwrite_NvdOverwritesOnlyItself() {
        // NVD should be able to overwrite itself and null
        assertTrue(RatingSource.NVD.canOverwrite(RatingSource.NVD));
        assertTrue(RatingSource.NVD.canOverwrite(null));

        // NVD should NOT be able to overwrite any higher precedence source
        assertFalse(RatingSource.NVD.canOverwrite(RatingSource.MANUAL));
        assertFalse(RatingSource.NVD.canOverwrite(RatingSource.VEX));
        assertFalse(RatingSource.NVD.canOverwrite(RatingSource.POLICY));
    }

    @Test
    void testCanOverwrite_NullSource() {
        // All sources should be able to overwrite null (no existing rating)
        assertTrue(RatingSource.MANUAL.canOverwrite(null));
        assertTrue(RatingSource.VEX.canOverwrite(null));
        assertTrue(RatingSource.POLICY.canOverwrite(null));
        assertTrue(RatingSource.NVD.canOverwrite(null));
    }

    @Test
    void testRealWorldScenario_ManualOverridesVex() {
        // Scenario: Security analyst manually sets OWASP score to 9.0 after investigation
        // Later, a VEX document with score 7.2 is imported
        // The manual rating should be preserved
        assertFalse(RatingSource.VEX.canOverwrite(RatingSource.MANUAL),
                "VEX import should not overwrite manual analyst assessment");
    }

    @Test
    void testRealWorldScenario_VexOverridesPolicy() {
        // Scenario: Organizational policy sets SQLi vulns to 8.0 minimum
        // Later, a context-aware VEX document with score 7.2 is imported
        // The VEX rating should overwrite the policy
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.POLICY),
                "Context-aware VEX ratings should overwrite generic policy ratings");
    }

    @Test
    void testRealWorldScenario_VexUpdatesVex() {
        // Scenario: First VEX import sets score to 7.2
        // Later, an updated VEX document with revised score 8.5 is imported
        // The new VEX rating should overwrite the old one
        assertTrue(RatingSource.VEX.canOverwrite(RatingSource.VEX),
                "Updated VEX ratings should overwrite previous VEX ratings");
    }
}
