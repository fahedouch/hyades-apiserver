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

/**
 * Defines the source of a rating (CVSS or OWASP) in an analysis.
 * This enum is used to track the origin of ratings and enforce precedence rules
 * to prevent unintended overwrites.
 *
 * <p>Precedence order (highest to lowest):</p>
 * <ol>
 *   <li>{@link #POLICY} - Rating applied by organizational policies (highest precedence)</li>
 *   <li>{@link #VEX} - Rating from VEX (Vulnerability Exploitability eXchange) documents</li>
 *   <li>{@link #MANUAL} - User-provided rating</li>
 *   <li>{@link #NVD} - Default rating from the National Vulnerability Database</li>
 * </ol>
 *
 * <p>Rationale: POLICY has highest precedence to enforce organizational security standards.
 * VEX can overwrite MANUAL assessments as it represents authoritative context-aware analysis.
 * MANUAL ratings serve as analyst notes but are subject to policy enforcement.</p>
 *
 * @since 5.8.0
 */
public enum RatingSource {

    /**
     * Rating applied by an organizational policy.
     * Has the highest precedence to enforce security standards across the organization.
     * Cannot be overwritten by MANUAL, VEX, or NVD ratings.
     */
    POLICY(4),

    /**
     * Rating imported from a VEX (Vulnerability Exploitability eXchange) document.
     * VEX ratings are context-specific and reflect authoritative risk assessment.
     * Can overwrite MANUAL and NVD ratings, but not POLICY ratings.
     */
    VEX(3),

    /**
     * Rating manually set by a security analyst or user.
     * Can overwrite NVD ratings, but not POLICY or VEX ratings.
     * Serves as analyst notes subject to policy enforcement.
     */
    MANUAL(2),

    /**
     * Default rating from the National Vulnerability Database (NVD) or other vulnerability sources.
     * This has the lowest precedence and can be overwritten by any other source.
     */
    NVD(1);

    private final int precedence;

    RatingSource(int precedence) {
        this.precedence = precedence;
    }

    /**
     * Returns the precedence level of this rating source.
     * Higher values indicate higher precedence.
     *
     * @return the precedence level
     */
    public int getPrecedence() {
        return precedence;
    }

    /**
     * Determines if this rating source can overwrite another rating source.
     *
     * @param other the rating source to compare against
     * @return true if this source can overwrite the other source
     */
    public boolean canOverwrite(RatingSource other) {
        if (other == null) {
            return true;
        }
        return this.precedence >= other.precedence;
    }
}
