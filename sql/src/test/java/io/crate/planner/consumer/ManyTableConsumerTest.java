/*
 * Licensed to Crate under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.  Crate licenses this file
 * to you under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * However, if you have executed another commercial license agreement
 * with Crate these terms will supersede the license and you may use the
 * software solely pursuant to the terms of the relevant commercial
 * agreement.
 */

package io.crate.planner.consumer;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import io.crate.action.sql.SessionContext;
import io.crate.analyze.Analysis;
import io.crate.analyze.MultiSourceSelect;
import io.crate.analyze.ParameterContext;
import io.crate.analyze.SelectAnalyzedStatement;
import io.crate.analyze.TwoTableJoin;
import io.crate.analyze.relations.JoinPair;
import io.crate.analyze.symbol.Symbol;
import io.crate.planner.node.dql.join.JoinType;
import io.crate.sql.parser.SqlParser;
import io.crate.sql.tree.QualifiedName;
import io.crate.test.integration.CrateDummyClusterServiceUnitTest;
import io.crate.testing.SQLExecutor;
import io.crate.testing.SqlExpressions;
import io.crate.testing.T3;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.crate.testing.TestingHelpers.isSQL;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;

public class ManyTableConsumerTest extends CrateDummyClusterServiceUnitTest {

    private SQLExecutor e;
    private final SqlExpressions expressions = new SqlExpressions(T3.SOURCES);

    @Before
    public void prepare() {
        e = SQLExecutor.builder(clusterService).enableDefaultTables().build();
    }

    private MultiSourceSelect analyze(String statement) {
        Analysis analysis = e.analyzer.boundAnalyze(
            SqlParser.createStatement(statement), SessionContext.SYSTEM_SESSION, ParameterContext.EMPTY);
        return (MultiSourceSelect) ((SelectAnalyzedStatement) analysis.analyzedStatement()).relation();
    }

    @Test
    public void testQuerySplitting() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1 " +
                                        "join t2 on t1.a = t2.b " +
                                        "join t3 on t2.b = t3.c " +
                                        "order by t1.a, t2.b, t3.c");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        TwoTableJoin t1AndT2 = (TwoTableJoin) root.left();

        assertThat(t1AndT2.joinPair().condition(), isSQL("(doc.t1.a = doc.t2.b)"));
        assertThat(root.joinPair().condition(), isSQL("(join.doc.t1.doc.t2.doc.t2['b'] = doc.t3.c)"));
    }

    @Test
    public void testQuerySplittingWithRelationReOrdering() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1, t2, t3 " +
                                        "where t3.c = t2.b " +
                                        "order by t3.c");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        TwoTableJoin left = (TwoTableJoin) root.left();

        assertThat(left.querySpec().where().query(), isSQL("(doc.t3.c = doc.t2.b)"));
    }

    @Test
    public void testQuerySplittingWithBadRelationOrder() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1 " +
                                        "join t2 on t1.a = t2.b " +
                                        "join t3 on t2.b = t3.c " +
                                        "order by t3.c, t1.a, t2.b");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        assertThat(root.toString(), is("join.join.doc.t3.doc.t1.doc.t2"));

        TwoTableJoin t3AndT1 = (TwoTableJoin) root.left();
        assertThat(t3AndT1.toString(), is("join.doc.t3.doc.t1"));
        assertThat(t3AndT1.querySpec().where().query(), isSQL("null"));

        assertThat(root.joinPair().condition(),
            isSQL("((join.doc.t3.doc.t1.doc.t1['a'] = doc.t2.b) AND (doc.t2.b = join.doc.t3.doc.t1.doc.t3['c']))"));
    }

    @Test
    public void testQuerySplittingReplacesCopiedSymbols() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1, t2 " +
                                        "where t1.x = 1 or t2.y = 1 " +
                                        "order by t1.x + t1.x");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        assertThat(root.querySpec().orderBy().get().orderBySymbols(), isSQL("add(doc.t1.x, doc.t1.x)"));
        assertThat(root.left().querySpec().orderBy().get().orderBySymbols(), isSQL("add(doc.t1.x, doc.t1.x)"));
    }

    @Test
    public void testOptimizeJoinNoPresort() throws Exception {
        JoinPair pair1 = JoinPair.crossJoin(T3.T1, T3.T2);
        JoinPair pair2 = JoinPair.crossJoin(T3.T2, T3.T3);
        @SuppressWarnings("unchecked")
        Collection<QualifiedName> qualifiedNames = ManyTableConsumer.orderByJoinConditions(
            Arrays.asList(T3.T1, T3.T2, T3.T3),
            ImmutableSet.of(),
            ImmutableSet.of(),
            ImmutableList.of(pair1, pair2),
            ImmutableList.of());

        assertThat(qualifiedNames, contains(T3.T1, T3.T2, T3.T3));
    }

    @Test
    public void testOptimizeJoinWithoutJoinConditionsAndPreSort() throws Exception {
        Collection<QualifiedName> qualifiedNames = ManyTableConsumer.orderByJoinConditions(
            Arrays.asList(T3.T1, T3.T2, T3.T3),
            ImmutableSet.of(),
            ImmutableSet.of(),
            ImmutableList.of(),
            ImmutableList.of(T3.T2));

        assertThat(qualifiedNames, contains(T3.T2, T3.T1, T3.T3));
    }

    @Test
    public void testNoOptimizeWithSortingAndOuterJoin() throws Exception {
        JoinPair pair1 = JoinPair.of(T3.T1, T3.T2, JoinType.LEFT, expressions.asSymbol("t1.a = t2.b"));
        JoinPair pair2 = JoinPair.of(T3.T2, T3.T3, JoinType.LEFT, expressions.asSymbol("t2.b = t3.c"));
        @SuppressWarnings("unchecked")
        Collection<QualifiedName> qualifiedNames = ManyTableConsumer.orderByJoinConditions(
            Arrays.asList(T3.T1, T3.T2, T3.T3),
            ImmutableSet.of(),
            ImmutableSet.of(),
            ImmutableList.of(pair1, pair2),
            ImmutableList.of(T3.T3, T3.T2));

        assertThat(qualifiedNames, contains(T3.T1, T3.T2, T3.T3));
    }

    @Test
    public void testSortOnOuterJoinOuterRelation() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1 " +
                                        "left join t2 on t1.a = t2.b " +
                                        "order by t2.b");
        TwoTableJoin root = ManyTableConsumer.twoTableJoin(mss);

        assertThat(root.right().querySpec().orderBy().isPresent(), is(false));
        assertThat(root.querySpec().orderBy().get(), isSQL("doc.t2.b"));
    }

    @Test
    public void test3TableSortOnOuterJoinOuterRelation() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1 " +
                                        "left join t2 on t1.a = t2.b " +
                                        "left join t3 on t2.b = t3.c " +
                                        "order by t2.b, t3.c");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        TwoTableJoin t1AndT2 = (TwoTableJoin) root.left();

        assertThat(t1AndT2.right().querySpec().orderBy().isPresent(), is(false));
        assertThat(t1AndT2.querySpec().orderBy().get(), isSQL("doc.t2.b"));

        assertThat(root.right().querySpec().orderBy().isPresent(), is(false));
        assertThat(root.querySpec().orderBy().get(), isSQL("join.doc.t1.doc.t2.doc.t2['b'], doc.t3.c"));
    }

    @Test
    public void testJoinConditionsAreRewrittenIfOutputsChanges() throws Exception {
        MultiSourceSelect mss = analyze("select t1.a from t1 " +
                                        "left join t2 on t1.a = t2.b " +
                                        "where t1.x = 1 and t2.y in (1)");
        TwoTableJoin root = ManyTableConsumer.twoTableJoin(mss);
        // if Rewriter does not operate correctly on the joinPairs, t2 RelationColumn index would be 1 instead of 0
        // 2 outputs, t2.y + t2.b on t2 are rewritten to t2.b only because whereClause outputs must not be collected
        // so index for t2.b must be shifted
        assertThat(root.joinPair().condition(), isSQL("(doc.t1.a = doc.t2.b)"));
    }

    @Test
    public void test3TableSortOnWhere() throws Exception {
        MultiSourceSelect mss = analyze("select * from t1,t2,t3 " +
                                        "where t1.a=t3.c");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        assertThat(root.toString(), is("join.join.doc.t1.doc.t3.doc.t2"));
        TwoTableJoin t1Andt3 = (TwoTableJoin) root.left();
        assertThat(t1Andt3.toString(), is("join.doc.t1.doc.t3"));
        assertThat(root.right().getQualifiedName().toString(), is("doc.t2"));
    }

    @Test
    public void testReordering4TableSortOnWhereAndJoinConditionsThatDontMatchThePair() throws Exception {
        List<QualifiedName> relations = ImmutableList.of(
            T3.T1,
            T3.T2,
            T3.T3,
            T3.T4);
        List<JoinPair> joinPairs = ImmutableList.of(
            JoinPair.of(T3.T1, T3.T2, JoinType.INNER, expressions.asSymbol("t1.a=t2.b")),
            JoinPair.of(T3.T2, T3.T3, JoinType.INNER, expressions.asSymbol("t2.b=t1.a")),
            JoinPair.of(T3.T4, T3.T3, JoinType.INNER, expressions.asSymbol("t4.id=t3.c")));
        assertThat(ManyTableConsumer.orderByJoinConditions(
            relations,
            Collections.emptySet(),
            Collections.emptySet(),
            joinPairs,
            ImmutableList.of(T3.T4)), contains(T3.T4, T3.T1, T3.T2, T3.T3));
    }

    @Test
    public void test4TableSortOnWhereAndJoinConditionsThatDontMatchThePair() throws Exception {
        MultiSourceSelect mss = analyze("select *" +
                                        " from t1" +
                                        " join t2 on t1.a=t2.b and (t2.b=10 or t1.a=20) " +
                                        " join t3 on t2.b=t3.c" +
                                        " join users on t1.i=users.id" +
                                        " join users_multi_pk on t3.z=users_multi_pk.id" +
                                        " order by t3.c");
        TwoTableJoin root = ManyTableConsumer.buildTwoTableJoinTree(mss);
        assertThat(root.toString(), is("join.join.join.join.doc.t3.doc.users_multi_pk.doc.users.doc.t1.doc.t2"));
        assertThat(root.joinPair().condition(),
                   isSQL("(((join.join.join.doc.t3.doc.users_multi_pk.doc.users.doc.t1.doc.t1['a'] = doc.t2.b) " +
                         "AND ((doc.t2.b = '10') OR (join.join.join.doc.t3.doc.users_multi_pk.doc.users.doc.t1.doc." +
                         "t1['a'] = '20'))) AND (doc.t2.b = join.join.join.doc.t3.doc.users_multi_pk.doc.users.doc." +
                         "t1.\"join.join.doc.t3.doc.users_multi_pk.doc.users\"['join.doc.t3.doc.users_multi_pk" +
                         "['doc.t3['c']']']))"));
        TwoTableJoin tt1 = (TwoTableJoin) root.left();
        assertThat(tt1.toString(), is("join.join.join.doc.t3.doc.users_multi_pk.doc.users.doc.t1"));
        assertThat(tt1.joinPair().condition(),
                   isSQL("(doc.t1.i = to_int(join.join.doc.t3.doc.users_multi_pk.doc.users.doc.users['id']))"));
        TwoTableJoin tt2 = (TwoTableJoin) tt1.left();
        assertThat(tt2.toString(), is("join.join.doc.t3.doc.users_multi_pk.doc.users"));
        assertThat(tt2.joinPair().condition(), nullValue());

        TwoTableJoin tt3 = (TwoTableJoin) tt2.left();
        assertThat(tt3.toString(), is("join.doc.t3.doc.users_multi_pk"));
        assertThat(tt3.joinPair().condition(), isSQL("(doc.t3.z = to_int(doc.users_multi_pk.id))"));
    }

    @Test
    public void testBuildingOfJoinConditionsMap() {
        List<JoinPair> joinPairs = ImmutableList.of(
            JoinPair.of(T3.T1, T3.T2, JoinType.INNER, expressions.asSymbol("t1.a=t2.b")),
            JoinPair.of(T3.T2, T3.T3, JoinType.INNER, expressions.asSymbol("t2.b=t1.a and t2.b=t3.c")),
            JoinPair.of(T3.T4, T3.T3, JoinType.INNER,
                        expressions.asSymbol("t4.id=t3.z and (t2.b=t3.c or t4.id=t1.x)")));


        Map<Set<QualifiedName>, Symbol> joinConditions = ManyTableConsumer.buildJoinConditionsMap(joinPairs);
        assertThat(joinConditions.size(), is(4));
        assertThat(joinConditions.get(ImmutableSet.of(T3.T1, T3.T2)),
                   isSQL("((doc.t1.a = doc.t2.b) AND (doc.t2.b = doc.t1.a))"));
        assertThat(joinConditions.get(ImmutableSet.of(T3.T2, T3.T3)), isSQL("(doc.t2.b = doc.t3.c)"));
        assertThat(joinConditions.get(ImmutableSet.of(T3.T3, T3.T4)), isSQL("(doc.t4.id = doc.t3.z)"));
        assertThat(joinConditions.get(ImmutableSet.of(T3.T1, T3.T2, T3.T3, T3.T4)),
                   isSQL("((doc.t2.b = doc.t3.c) OR (doc.t4.id = doc.t1.x))"));
    }
}
