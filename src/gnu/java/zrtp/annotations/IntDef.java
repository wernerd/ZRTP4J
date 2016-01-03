package gnu.java.zrtp.annotations;

/**
 * Annotations to check for allowed integer constants.
 *
 * Shamelessly copied from Android's IntDef annotation: core/java/android/annotation/IntDef.java
 *
 * Created by werner on 03.01.16.
 */
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.RetentionPolicy.CLASS;

@Retention(CLASS)
@Target({ANNOTATION_TYPE})
public @interface IntDef {
    /** Defines the allowed constants for this element */
    long[] value() default {};
    /** Defines whether the constants can be used as a flag, or just as an enum (the default) */
    boolean flag() default false;
}
