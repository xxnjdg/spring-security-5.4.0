/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.method.configuration;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;

/**
 * <p>
 * Enables Spring Security global method security similar to the
 * &lt;global-method-security&gt; xml support.
 *
 * <p>
 * More advanced configurations may wish to extend
 * {@link GlobalMethodSecurityConfiguration} and override the protected methods to provide
 * custom implementations. Note that {@link EnableGlobalMethodSecurity} still must be
 * included on the class extending {@link GlobalMethodSecurityConfiguration} to determine
 * the settings.
 *
 * @author Rob Winch
 * @since 3.2
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import({ GlobalMethodSecuritySelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableGlobalMethodSecurity {

	/**
	 * Determines if Spring Security's pre post annotations should be enabled. Default is
	 * false.
	 * @return true if pre post annotations should be enabled false otherwise.
	 */
	boolean prePostEnabled() default false;

	/**
	 * Determines if Spring Security's {@link Secured} annotations should be enabled.
	 * @return true if {@link Secured} annotations should be enabled false otherwise.
	 * Default is false.
	 */
	boolean securedEnabled() default false;

	/**
	 * Determines if JSR-250 annotations should be enabled. Default is false.
	 * @return true if JSR-250 should be enabled false otherwise.
	 */
	boolean jsr250Enabled() default false;

	/**
	 * Indicate whether subclass-based (CGLIB) proxies are to be created ({@code true}) as
	 * opposed to standard Java interface-based proxies ({@code false}). The default is
	 * {@code false}. <strong>Applicable only if {@link #mode()} is set to
	 * {@link AdviceMode#PROXY}</strong>.
	 *
	 * 指示是否要创建基于子类（CGLIB）的代理（{@code true}），而不是基于标准Java接口的代理（{@code false}）。
	 * 默认值为{@code false}。 <strong>仅在{@link #mode（）}设置为{@link AdviceMode＃PROXY}时适用</ strong>。
	 *
	 * <p>
	 * Note that setting this attribute to {@code true} will affect <em>all</em>
	 * Spring-managed beans requiring proxying, not just those marked with the Security
	 * annotations. For example, other beans marked with Spring's {@code @Transactional}
	 * annotation will be upgraded to subclass proxying at the same time. This approach
	 * has no negative impact in practice unless one is explicitly expecting one type of
	 * proxy vs another, e.g. in tests.
	 * @return true if CGILIB proxies should be created instead of interface based
	 * proxies, else false
	 *
	 * 请注意，将此属性设置为{@code true}会影响所有需要代理的<em> all </ em> Spring管理的bean，而不仅仅是那些标记有Security批注的bean。
	 * 例如，其他标有Spring的{@code @Transactional}批注的bean将同时升级为子类代理。 这种方法在实践中不会产生负面影响，
	 * 除非一个人明确期望一种类型的代理与另一种类型的代理，例如 在测试中。 @return如果应创建CGILIB代理而不是基于接口的代理，则为true，否则为false
	 */
	boolean proxyTargetClass() default false;

	/**
	 * Indicate how security advice should be applied. The default is
	 * {@link AdviceMode#PROXY}.
	 * @see AdviceMode
	 * @return the {@link AdviceMode} to use
	 */
	AdviceMode mode() default AdviceMode.PROXY;

	/**
	 * Indicate the ordering of the execution of the security advisor when multiple
	 * advices are applied at a specific joinpoint. The default is
	 * {@link Ordered#LOWEST_PRECEDENCE}.
	 * @return the order the security advisor should be applied
	 */
	int order() default Ordered.LOWEST_PRECEDENCE;

}
