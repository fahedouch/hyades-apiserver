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
package org.dependencytrack.persistence;

import alpine.model.ApiKey;
import alpine.model.User;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RatingSource;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class AnalysisQueryManager extends QueryManager implements IQueryManager {


    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    AnalysisQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    AnalysisQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a List Analysis for the specified Project.
     *
     * @param project the Project
     * @return a List of Analysis objects, or null if not found
     */
    @SuppressWarnings("unchecked")
    List<Analysis> getAnalyses(Project project) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "project == :project");
        return (List<Analysis>) query.execute(project);
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     *
     * @param component     the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        final Query<Analysis> query = pm.newQuery(Analysis.class, "component == :component && vulnerability == :vulnerability");
        query.setRange(0, 1);
        return singleResult(query.execute(component, vulnerability));
    }

    /**
     * @since 5.7.0
     */
    @Override
    public long makeAnalysis(final MakeAnalysisCommand command) {
        assertPersistent(command.component(), "component must be persistent");
        assertPersistent(command.vulnerability(), "vulnerability must be persistent");

        return callInTransaction(() -> {
            final var auditTrailComments = new ArrayList<String>();

            Analysis analysis = getAnalysis(command.component(), command.vulnerability());
            if (analysis == null) {
                analysis = new Analysis();
                analysis.setComponent(command.component());
                analysis.setVulnerability(command.vulnerability());
                analysis.setAnalysisState(AnalysisState.NOT_SET);
                analysis.setAnalysisJustification(AnalysisJustification.NOT_SET);
                analysis.setAnalysisResponse(AnalysisResponse.NOT_SET);
                analysis.setSuppressed(false);
                persist(analysis);
            }

            boolean stateChanged = false;
            boolean suppressionChanged = false;

            if (command.state() != null && command.state() != analysis.getAnalysisState()) {
                auditTrailComments.add("Analysis: %s → %s".formatted(analysis.getAnalysisState(), command.state()));
                analysis.setAnalysisState(command.state());
                stateChanged = true;
            }
            if (command.justification() != null && command.justification() != analysis.getAnalysisJustification()) {
                auditTrailComments.add("Justification: %s → %s".formatted(analysis.getAnalysisJustification(), command.justification()));
                analysis.setAnalysisJustification(command.justification());
            }
            if (command.response() != null && command.response() != analysis.getAnalysisResponse()) {
                auditTrailComments.add("Vendor Response: %s → %s".formatted(analysis.getAnalysisResponse(), command.response()));
                analysis.setAnalysisResponse(command.response());
            }
            if (command.details() != null && !command.details().equals(analysis.getAnalysisDetails())) {
                auditTrailComments.add("Details: %s".formatted(command.details()));
                analysis.setAnalysisDetails(command.details());
            }
            if (command.suppress() != null && command.suppress() != analysis.isSuppressed()) {
                auditTrailComments.add(command.suppress() ? "Suppressed" : "Unsuppressed");
                analysis.setSuppressed(command.suppress());
                suppressionChanged = true;
            }

            // Handle CVSS v2 rating with precedence
            if (command.cvssV2Vector() != null || command.cvssV2Score() != null) {
                if (canUpdateRating(analysis.getCvssV2Source(), command.cvssV2Source())) {
                    if (command.cvssV2Vector() != null && !command.cvssV2Vector().equals(analysis.getCvssV2Vector())) {
                        auditTrailComments.add("CVSS v2 Vector: %s → %s (Source: %s)".formatted(
                                analysis.getCvssV2Vector(), command.cvssV2Vector(), command.cvssV2Source()));
                        analysis.setCvssV2Vector(command.cvssV2Vector());
                    }
                    if (command.cvssV2Score() != null && !command.cvssV2Score().equals(analysis.getCvssV2Score())) {
                        auditTrailComments.add("CVSS v2 Score: %s → %s (Source: %s)".formatted(
                                analysis.getCvssV2Score(), command.cvssV2Score(), command.cvssV2Source()));
                        analysis.setCvssV2Score(command.cvssV2Score());
                    }
                    analysis.setCvssV2Source(command.cvssV2Source());
                }
            }

            // Handle CVSS v3 rating with precedence
            if (command.cvssV3Vector() != null || command.cvssV3Score() != null) {
                if (canUpdateRating(analysis.getCvssV3Source(), command.cvssV3Source())) {
                    if (command.cvssV3Vector() != null && !command.cvssV3Vector().equals(analysis.getCvssV3Vector())) {
                        auditTrailComments.add("CVSS v3 Vector: %s → %s (Source: %s)".formatted(
                                analysis.getCvssV3Vector(), command.cvssV3Vector(), command.cvssV3Source()));
                        analysis.setCvssV3Vector(command.cvssV3Vector());
                    }
                    if (command.cvssV3Score() != null && !command.cvssV3Score().equals(analysis.getCvssV3Score())) {
                        auditTrailComments.add("CVSS v3 Score: %s → %s (Source: %s)".formatted(
                                analysis.getCvssV3Score(), command.cvssV3Score(), command.cvssV3Source()));
                        analysis.setCvssV3Score(command.cvssV3Score());
                    }
                    analysis.setCvssV3Source(command.cvssV3Source());
                }
            }

            // Handle CVSS v4 rating with precedence
            if (command.cvssV4Vector() != null || command.cvssV4Score() != null) {
                if (canUpdateRating(analysis.getCvssV4Source(), command.cvssV4Source())) {
                    if (command.cvssV4Vector() != null && !command.cvssV4Vector().equals(analysis.getCvssV4Vector())) {
                        auditTrailComments.add("CVSS v4 Vector: %s → %s (Source: %s)".formatted(
                                analysis.getCvssV4Vector(), command.cvssV4Vector(), command.cvssV4Source()));
                        analysis.setCvssV4Vector(command.cvssV4Vector());
                    }
                    if (command.cvssV4Score() != null && !command.cvssV4Score().equals(analysis.getCvssV4Score())) {
                        auditTrailComments.add("CVSS v4 Score: %s → %s (Source: %s)".formatted(
                                analysis.getCvssV4Score(), command.cvssV4Score(), command.cvssV4Source()));
                        analysis.setCvssV4Score(command.cvssV4Score());
                    }
                    analysis.setCvssV4Source(command.cvssV4Source());
                }
            }

            // Handle OWASP rating with precedence
            if (command.owaspVector() != null || command.owaspScore() != null) {
                if (canUpdateRating(analysis.getOwaspSource(), command.owaspSource())) {
                    if (command.owaspVector() != null && !command.owaspVector().equals(analysis.getOwaspVector())) {
                        auditTrailComments.add("OWASP RR Vector: %s → %s (Source: %s)".formatted(
                                analysis.getOwaspVector(), command.owaspVector(), command.owaspSource()));
                        analysis.setOwaspVector(command.owaspVector());
                    }
                    if (command.owaspScore() != null && !command.owaspScore().equals(analysis.getOwaspScore())) {
                        auditTrailComments.add("OWASP RR Score: %s → %s (Source: %s)".formatted(
                                analysis.getOwaspScore(), command.owaspScore(), command.owaspSource()));
                        analysis.setOwaspScore(command.owaspScore());
                    }
                    analysis.setOwaspSource(command.owaspSource());
                }
            }

            final List<String> comments =
                    !command.options().contains(MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL)
                            ? auditTrailComments
                            : new ArrayList<>();
            if (command.comment() != null) {
                comments.add(command.comment());
            }

            createAnalysisComments(analysis, command.commenter(), comments);

            if (!command.options().contains(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)
                    && (stateChanged || suppressionChanged)) {
                new JdoNotificationEmitter(this).emit(
                        createVulnerabilityAnalysisDecisionChangeNotification(
                                NotificationModelConverter.convert(analysis.getProject()),
                                NotificationModelConverter.convert(analysis.getComponent()),
                                NotificationModelConverter.convert(analysis.getVulnerability()),
                                NotificationModelConverter.convert(analysis),
                                stateChanged,
                                suppressionChanged));
            }

            return analysis.getId();
        });
    }

    private void createAnalysisComments(
            final Analysis analysis,
            final String commenter,
            final List<String> comments) {
        assertPersistent(analysis, "analysis must be persistent");

        if (comments == null || comments.isEmpty()) {
            return;
        }

        final var now = new Date();

        final String commenterToUse;
        if (commenter == null) {
            commenterToUse = switch (principal) {
                case User user -> user.getUsername();
                case ApiKey apiKey -> apiKey.getTeams().get(0).getName();
                case null -> null;
                default -> throw new IllegalStateException(
                        "Unexpected principal type: " + principal.getClass().getName());
            };
        } else {
            commenterToUse = commenter;
        }

        runInTransaction(() -> {
            final var analysisComments = new ArrayList<AnalysisComment>(comments.size());

            for (final String comment : comments) {
                final var analysisComment = new AnalysisComment();
                analysisComment.setAnalysis(analysis);
                analysisComment.setCommenter(commenterToUse);
                analysisComment.setComment(comment);
                analysisComment.setTimestamp(now);
                analysisComments.add(analysisComment);
            }

            persist(analysisComments);

            if (analysis.getAnalysisComments() != null) {
                analysis.getAnalysisComments().addAll(analysisComments);
            } else {
                analysis.setAnalysisComments(analysisComments);
            }
        });
    }

    /**
     * Determines if a rating can be updated based on the precedence rules of rating sources.
     * <p>
     * Precedence order (highest to lowest):
     * <ol>
     *   <li>MANUAL - User-provided ratings</li>
     *   <li>VEX - Ratings from VEX documents</li>
     *   <li>POLICY - Ratings from organizational policies</li>
     *   <li>NVD - Default ratings from vulnerability databases</li>
     * </ol>
     *
     * @param existingSource the current rating source (may be null if no rating exists)
     * @param newSource      the new rating source attempting to update the rating
     * @return true if the new source can overwrite the existing source, false otherwise
     */
    private boolean canUpdateRating(final RatingSource existingSource, final RatingSource newSource) {
        if (newSource == null) {
            return false;
        }
        return newSource.canOverwrite(existingSource);
    }

}
