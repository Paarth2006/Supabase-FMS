


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE SCHEMA IF NOT EXISTS "public";


ALTER SCHEMA "public" OWNER TO "pg_database_owner";


COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE TYPE "public"."assignment_status" AS ENUM (
    'assigned',
    'unassigned',
    'transferred'
);


ALTER TYPE "public"."assignment_status" OWNER TO "postgres";


CREATE TYPE "public"."geofence_event_type" AS ENUM (
    'entered',
    'exited',
    'violation'
);


ALTER TYPE "public"."geofence_event_type" OWNER TO "postgres";


CREATE TYPE "public"."inspection_result" AS ENUM (
    'passed',
    'failed'
);


ALTER TYPE "public"."inspection_result" OWNER TO "postgres";


CREATE TYPE "public"."inspection_type" AS ENUM (
    'pre_trip',
    'post_trip'
);


ALTER TYPE "public"."inspection_type" OWNER TO "postgres";


CREATE TYPE "public"."inventory_transaction_type" AS ENUM (
    'stock_in',
    'stock_out',
    'adjustment'
);


ALTER TYPE "public"."inventory_transaction_type" OWNER TO "postgres";


CREATE TYPE "public"."issue_severity" AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);


ALTER TYPE "public"."issue_severity" OWNER TO "postgres";


CREATE TYPE "public"."issue_status" AS ENUM (
    'open',
    'in_progress',
    'resolved'
);


ALTER TYPE "public"."issue_status" OWNER TO "postgres";


CREATE TYPE "public"."kyc_status" AS ENUM (
    'pending',
    'approved',
    'rejected'
);


ALTER TYPE "public"."kyc_status" OWNER TO "postgres";


CREATE TYPE "public"."maintenance_priority" AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);


ALTER TYPE "public"."maintenance_priority" OWNER TO "postgres";


CREATE TYPE "public"."maintenance_request_status" AS ENUM (
    'pending',
    'approved',
    'rejected',
    'assigned',
    'completed'
);


ALTER TYPE "public"."maintenance_request_status" OWNER TO "postgres";


CREATE TYPE "public"."maintenance_schedule_status" AS ENUM (
    'scheduled',
    'overdue',
    'completed'
);


ALTER TYPE "public"."maintenance_schedule_status" OWNER TO "postgres";


CREATE TYPE "public"."predictive_alert_status" AS ENUM (
    'new',
    'acknowledged',
    'converted_to_request',
    'resolved'
);


ALTER TYPE "public"."predictive_alert_status" OWNER TO "postgres";


CREATE TYPE "public"."request_status" AS ENUM (
    'pending',
    'approved',
    'rejected'
);


ALTER TYPE "public"."request_status" OWNER TO "postgres";


CREATE TYPE "public"."trip_status" AS ENUM (
    'assigned',
    'accepted',
    'in_progress',
    'completed',
    'cancelled'
);


ALTER TYPE "public"."trip_status" OWNER TO "postgres";


CREATE TYPE "public"."user_role" AS ENUM (
    'admin',
    'fleet_manager',
    'driver',
    'maintenance_personnel'
);


ALTER TYPE "public"."user_role" OWNER TO "postgres";


CREATE TYPE "public"."vehicle_status" AS ENUM (
    'available',
    'assigned',
    'in_trip',
    'under_maintenance',
    'inactive'
);


ALTER TYPE "public"."vehicle_status" OWNER TO "postgres";


CREATE TYPE "public"."work_order_status" AS ENUM (
    'open',
    'in_progress',
    'waiting_for_parts',
    'on_hold',
    'completed'
);


ALTER TYPE "public"."work_order_status" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."admin_create_user"("p_email" "text", "p_password" "text", "p_role" "text", "p_full_name" "text", "p_phone" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_user_id UUID := gen_random_uuid();
  v_encrypted_password TEXT;
BEGIN
  -- Check if user already exists
  IF EXISTS (SELECT 1 FROM auth.users WHERE email = p_email) THEN
    RAISE EXCEPTION 'User with this email already exists';
  END IF;

  -- Hash the password
  v_encrypted_password := crypt(p_password, gen_salt('bf'));

  INSERT INTO auth.users (
    id,
    instance_id,
    aud,
    role,
    email,
    encrypted_password,
    email_confirmed_at,
    raw_app_meta_data,
    raw_user_meta_data,
    created_at,
    updated_at,
    confirmation_token,
    recovery_token
  ) VALUES (
    v_user_id,
    '00000000-0000-0000-0000-000000000000',
    'authenticated',
    'authenticated',
    p_email,
    v_encrypted_password,
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('full_name', p_full_name, 'phone', p_phone, 'role', p_role),
    now(),
    now(),
    '',
    ''
  );

  INSERT INTO auth.identities (
    id,
    user_id,
    provider_id,
    identity_data,
    provider,
    created_at,
    updated_at
  ) VALUES (
    gen_random_uuid(),
    v_user_id,
    v_user_id::text,
    jsonb_build_object('sub', v_user_id, 'email', p_email),
    'email',
    now(),
    now()
  );

  RETURN v_user_id;
END;
$$;


ALTER FUNCTION "public"."admin_create_user"("p_email" "text", "p_password" "text", "p_role" "text", "p_full_name" "text", "p_phone" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_user_exists_by_email"("lookup_email" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.app_users WHERE lower(email) = lower(lookup_email)
  );
END;
$$;


ALTER FUNCTION "public"."check_user_exists_by_email"("lookup_email" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."current_user_admin_owner_id"() RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select admin_owner_id
  from public.app_users
  where user_id = auth.uid()
    and is_active = true
  limit 1;
$$;


ALTER FUNCTION "public"."current_user_admin_owner_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_role public.user_role;
  v_admin_owner_id uuid;
  v_full_name text;
  v_phone text;
begin
  v_full_name := coalesce(
    nullif(new.raw_user_meta_data ->> 'full_name', ''),
    new.email
  );

  v_phone := nullif(new.raw_user_meta_data ->> 'phone', '');

  /*
    Case 1: User created by Edge Function
    - app_metadata contains role and admin_owner_id
    - used for driver, fleet_manager, maintenance_personnel

    Case 2: User signs up directly from iOS
    - treated as admin
    - admin_owner_id = own user_id
  */

  if new.raw_app_meta_data ? 'admin_owner_id' then
    v_role := (new.raw_app_meta_data ->> 'role')::public.user_role;
    v_admin_owner_id := (new.raw_app_meta_data ->> 'admin_owner_id')::uuid;
  else
    v_role := 'admin'::public.user_role;
    v_admin_owner_id := new.id;
  end if;

  insert into public.app_users (
    user_id,
    admin_owner_id,
    full_name,
    email,
    phone,
    role,
    is_active
  )
  values (
    new.id,
    v_admin_owner_id,
    v_full_name,
    new.email,
    v_phone,
    v_role,
    true
  )
  on conflict (user_id) do update
  set
    admin_owner_id = excluded.admin_owner_id,
    full_name = excluded.full_name,
    email = excluded.email,
    phone = excluded.phone,
    role = excluded.role,
    is_active = excluded.is_active,
    updated_at = now();

  return new;
end;
$$;


ALTER FUNCTION "public"."handle_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_current_user_admin"() RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists (
    select 1
    from public.app_users
    where user_id = auth.uid()
      and role = 'admin'
      and is_active = true
  );
$$;


ALTER FUNCTION "public"."is_current_user_admin"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
  new.updated_at = now();
  return new;
end;
$$;


ALTER FUNCTION "public"."set_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at_column"() OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."app_users" (
    "user_id" "uuid" NOT NULL,
    "admin_owner_id" "uuid" NOT NULL,
    "full_name" character varying(100) NOT NULL,
    "email" character varying(255) NOT NULL,
    "phone" character varying(20),
    "role" "public"."user_role" NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "admin_owner_for_admin" CHECK ((("role" <> 'admin'::"public"."user_role") OR ("admin_owner_id" = "user_id")))
);


ALTER TABLE "public"."app_users" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."driver_kyc" (
    "kyc_id" bigint NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "license_number" character varying(50) NOT NULL,
    "government_id" character varying(50),
    "verification_status" "public"."kyc_status" DEFAULT 'pending'::"public"."kyc_status",
    "verified_at" timestamp without time zone,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "license_expiry" "date"
);


ALTER TABLE "public"."driver_kyc" OWNER TO "postgres";


ALTER TABLE "public"."driver_kyc" ALTER COLUMN "kyc_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."driver_kyc_kyc_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."fuel_logs" (
    "fuel_log_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "driver_id" "uuid",
    "trip_id" bigint,
    "liters" numeric(10,2),
    "cost" numeric(10,2),
    "mileage" integer,
    "filled_at" timestamp without time zone DEFAULT "now"()
);


ALTER TABLE "public"."fuel_logs" OWNER TO "postgres";


ALTER TABLE "public"."fuel_logs" ALTER COLUMN "fuel_log_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."fuel_logs_fuel_log_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."geofence_events" (
    "event_id" bigint NOT NULL,
    "trip_id" bigint NOT NULL,
    "geofence_id" bigint NOT NULL,
    "event_type" "public"."geofence_event_type" NOT NULL,
    "event_time" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE "public"."geofence_events" OWNER TO "postgres";


ALTER TABLE "public"."geofence_events" ALTER COLUMN "event_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."geofence_events_event_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."geofences" (
    "geofence_id" bigint NOT NULL,
    "name" character varying(100) NOT NULL,
    "latitude" numeric(10,7) NOT NULL,
    "longitude" numeric(10,7) NOT NULL,
    "radius" numeric(10,2) NOT NULL,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "geofences_radius_check" CHECK (("radius" > (0)::numeric))
);


ALTER TABLE "public"."geofences" OWNER TO "postgres";


ALTER TABLE "public"."geofences" ALTER COLUMN "geofence_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."geofences_geofence_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."inventory_transactions" (
    "transaction_id" bigint NOT NULL,
    "part_id" bigint NOT NULL,
    "work_order_id" bigint,
    "transaction_type" "public"."inventory_transaction_type" NOT NULL,
    "quantity" integer NOT NULL,
    "created_at" timestamp without time zone DEFAULT "now"()
);


ALTER TABLE "public"."inventory_transactions" OWNER TO "postgres";


ALTER TABLE "public"."inventory_transactions" ALTER COLUMN "transaction_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."inventory_transactions_transaction_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."maintenance_records" (
    "record_id" bigint NOT NULL,
    "work_order_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "maintenance_type" character varying(100),
    "labor_cost" numeric(10,2) DEFAULT 0,
    "completion_notes" "text",
    "completed_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "parts_cost" numeric(10,2) DEFAULT 0,
    CONSTRAINT "maintenance_records_labor_cost_check" CHECK (("labor_cost" >= (0)::numeric))
);


ALTER TABLE "public"."maintenance_records" OWNER TO "postgres";


ALTER TABLE "public"."maintenance_records" ALTER COLUMN "record_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."maintenance_records_record_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."maintenance_requests" (
    "request_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "trip_id" bigint,
    "requested_by" "uuid" NOT NULL,
    "request_source" character varying(30) NOT NULL,
    "priority" "public"."maintenance_priority" DEFAULT 'medium'::"public"."maintenance_priority" NOT NULL,
    "description" "text" NOT NULL,
    "status" "public"."maintenance_request_status" DEFAULT 'pending'::"public"."maintenance_request_status" NOT NULL,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "maintenance_requests_request_source_check" CHECK ((("request_source")::"text" = ANY ((ARRAY['driver'::character varying, 'fleet_manager'::character varying, 'predictive_ai'::character varying, 'scheduled'::character varying])::"text"[])))
);


ALTER TABLE "public"."maintenance_requests" OWNER TO "postgres";


ALTER TABLE "public"."maintenance_requests" ALTER COLUMN "request_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."maintenance_requests_request_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."maintenance_schedules" (
    "schedule_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "maintenance_type" character varying(100) NOT NULL,
    "scheduled_date" "date",
    "target_mileage" integer,
    "target_usage_interval" integer,
    "status" "public"."maintenance_schedule_status" DEFAULT 'scheduled'::"public"."maintenance_schedule_status" NOT NULL,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "maintenance_schedules_target_mileage_check" CHECK (("target_mileage" >= 0)),
    CONSTRAINT "maintenance_schedules_target_usage_interval_check" CHECK (("target_usage_interval" >= 0))
);


ALTER TABLE "public"."maintenance_schedules" OWNER TO "postgres";


ALTER TABLE "public"."maintenance_schedules" ALTER COLUMN "schedule_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."maintenance_schedules_schedule_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."notifications" (
    "notification_id" bigint NOT NULL,
    "user_id" "uuid" NOT NULL,
    "title" character varying(150) NOT NULL,
    "message" "text",
    "is_read" boolean DEFAULT false,
    "created_at" timestamp without time zone DEFAULT "now"(),
    "notification_type" character varying(50)
);


ALTER TABLE "public"."notifications" OWNER TO "postgres";


ALTER TABLE "public"."notifications" ALTER COLUMN "notification_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."notifications_notification_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."predictive_maintenance_alerts" (
    "alert_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "alert_type" character varying(100) NOT NULL,
    "confidence_score" numeric(5,2),
    "recommendation" "text",
    "status" "public"."predictive_alert_status" DEFAULT 'new'::"public"."predictive_alert_status" NOT NULL,
    "maintenance_request_id" bigint,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "predictive_maintenance_alerts_confidence_score_check" CHECK ((("confidence_score" >= (0)::numeric) AND ("confidence_score" <= (100)::numeric)))
);


ALTER TABLE "public"."predictive_maintenance_alerts" OWNER TO "postgres";


ALTER TABLE "public"."predictive_maintenance_alerts" ALTER COLUMN "alert_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."predictive_maintenance_alerts_alert_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."route_deviation_requests" (
    "request_id" bigint NOT NULL,
    "trip_id" bigint NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "reason" "text" NOT NULL,
    "status" "public"."request_status" DEFAULT 'pending'::"public"."request_status",
    "requested_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "reviewed_at" timestamp without time zone
);


ALTER TABLE "public"."route_deviation_requests" OWNER TO "postgres";


ALTER TABLE "public"."route_deviation_requests" ALTER COLUMN "request_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."route_deviation_requests_request_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."routes" (
    "route_id" bigint NOT NULL,
    "route_name" character varying(100) NOT NULL,
    "start_location" "text" NOT NULL,
    "end_location" "text" NOT NULL,
    "distance_km" numeric(8,2),
    "estimated_duration_minutes" integer,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "routes_distance_km_check" CHECK (("distance_km" >= (0)::numeric)),
    CONSTRAINT "routes_estimated_duration_minutes_check" CHECK (("estimated_duration_minutes" >= 0))
);


ALTER TABLE "public"."routes" OWNER TO "postgres";


ALTER TABLE "public"."routes" ALTER COLUMN "route_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."routes_route_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."spare_parts" (
    "part_id" bigint NOT NULL,
    "part_name" character varying(150) NOT NULL,
    "description" "text",
    "current_stock" integer DEFAULT 0 NOT NULL,
    "minimum_stock" integer DEFAULT 5 NOT NULL,
    "reorder_level" integer DEFAULT 10 NOT NULL,
    "unit_cost" numeric(10,2),
    "storage_location" character varying(100),
    "created_at" timestamp without time zone DEFAULT "now"(),
    "updated_at" timestamp without time zone DEFAULT "now"()
);


ALTER TABLE "public"."spare_parts" OWNER TO "postgres";


ALTER TABLE "public"."spare_parts" ALTER COLUMN "part_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."spare_parts_part_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."trip_issues" (
    "issue_id" bigint NOT NULL,
    "trip_id" bigint NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "issue_type" character varying(100),
    "description" "text",
    "severity" "public"."issue_severity" DEFAULT 'medium'::"public"."issue_severity",
    "status" "public"."issue_status" DEFAULT 'open'::"public"."issue_status",
    "reported_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE "public"."trip_issues" OWNER TO "postgres";


ALTER TABLE "public"."trip_issues" ALTER COLUMN "issue_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."trip_issues_issue_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."trip_logs" (
    "log_id" bigint NOT NULL,
    "trip_id" bigint NOT NULL,
    "latitude" numeric(10,7),
    "longitude" numeric(10,7),
    "mileage" integer,
    "recorded_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "voice_transcript" "text",
    "start_location" "text",
    "end_location" "text",
    "distance_km" numeric(10,2),
    CONSTRAINT "trip_logs_mileage_check" CHECK (("mileage" >= 0))
);


ALTER TABLE "public"."trip_logs" OWNER TO "postgres";


ALTER TABLE "public"."trip_logs" ALTER COLUMN "log_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."trip_logs_log_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."trips" (
    "trip_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "route_id" bigint NOT NULL,
    "scheduled_start" timestamp without time zone NOT NULL,
    "actual_start" timestamp without time zone,
    "actual_end" timestamp without time zone,
    "status" "public"."trip_status" DEFAULT 'assigned'::"public"."trip_status" NOT NULL,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "actual_distance_km" numeric(10,2)
);


ALTER TABLE "public"."trips" OWNER TO "postgres";


ALTER TABLE "public"."trips" ALTER COLUMN "trip_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."trips_trip_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."vehicle_assignments" (
    "assignment_id" bigint NOT NULL,
    "vehicle_id" bigint NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "assigned_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "unassigned_at" timestamp without time zone,
    "status" "public"."assignment_status" DEFAULT 'assigned'::"public"."assignment_status",
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE "public"."vehicle_assignments" OWNER TO "postgres";


ALTER TABLE "public"."vehicle_assignments" ALTER COLUMN "assignment_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."vehicle_assignments_assignment_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."vehicle_inspections" (
    "inspection_id" bigint NOT NULL,
    "trip_id" bigint NOT NULL,
    "inspection_type" "public"."inspection_type" NOT NULL,
    "result" "public"."inspection_result" NOT NULL,
    "remarks" "text",
    "inspected_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE "public"."vehicle_inspections" OWNER TO "postgres";


ALTER TABLE "public"."vehicle_inspections" ALTER COLUMN "inspection_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."vehicle_inspections_inspection_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."vehicles" (
    "vehicle_id" bigint NOT NULL,
    "registration_number" character varying(20) NOT NULL,
    "make" character varying(50) NOT NULL,
    "model" character varying(50) NOT NULL,
    "manufacture_year" integer,
    "current_mileage" integer DEFAULT 0,
    "status" "public"."vehicle_status" DEFAULT 'available'::"public"."vehicle_status",
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "fuel_type" character varying(20),
    "capacity_kg" numeric(10,2),
    "Vehicle_Type" "text"
);


ALTER TABLE "public"."vehicles" OWNER TO "postgres";


ALTER TABLE "public"."vehicles" ALTER COLUMN "vehicle_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."vehicles_vehicle_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."work_order_parts" (
    "id" bigint NOT NULL,
    "work_order_id" bigint NOT NULL,
    "part_id" bigint NOT NULL,
    "quantity_used" integer NOT NULL,
    "created_at" timestamp without time zone DEFAULT "now"(),
    CONSTRAINT "work_order_parts_quantity_used_check" CHECK (("quantity_used" > 0))
);


ALTER TABLE "public"."work_order_parts" OWNER TO "postgres";


ALTER TABLE "public"."work_order_parts" ALTER COLUMN "id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."work_order_parts_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."work_orders" (
    "work_order_id" bigint NOT NULL,
    "maintenance_request_id" bigint NOT NULL,
    "maintenance_personnel_id" "uuid" NOT NULL,
    "status" "public"."work_order_status" DEFAULT 'open'::"public"."work_order_status" NOT NULL,
    "started_at" timestamp without time zone,
    "completed_at" timestamp without time zone,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE "public"."work_orders" OWNER TO "postgres";


ALTER TABLE "public"."work_orders" ALTER COLUMN "work_order_id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."work_orders_work_order_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



ALTER TABLE ONLY "public"."app_users"
    ADD CONSTRAINT "app_users_email_key" UNIQUE ("email");



ALTER TABLE ONLY "public"."app_users"
    ADD CONSTRAINT "app_users_pkey" PRIMARY KEY ("user_id");



ALTER TABLE ONLY "public"."driver_kyc"
    ADD CONSTRAINT "driver_kyc_license_number_key" UNIQUE ("license_number");



ALTER TABLE ONLY "public"."driver_kyc"
    ADD CONSTRAINT "driver_kyc_pkey" PRIMARY KEY ("kyc_id");



ALTER TABLE ONLY "public"."fuel_logs"
    ADD CONSTRAINT "fuel_logs_pkey" PRIMARY KEY ("fuel_log_id");



ALTER TABLE ONLY "public"."geofence_events"
    ADD CONSTRAINT "geofence_events_pkey" PRIMARY KEY ("event_id");



ALTER TABLE ONLY "public"."geofences"
    ADD CONSTRAINT "geofences_pkey" PRIMARY KEY ("geofence_id");



ALTER TABLE ONLY "public"."inventory_transactions"
    ADD CONSTRAINT "inventory_transactions_pkey" PRIMARY KEY ("transaction_id");



ALTER TABLE ONLY "public"."maintenance_records"
    ADD CONSTRAINT "maintenance_records_pkey" PRIMARY KEY ("record_id");



ALTER TABLE ONLY "public"."maintenance_requests"
    ADD CONSTRAINT "maintenance_requests_pkey" PRIMARY KEY ("request_id");



ALTER TABLE ONLY "public"."maintenance_schedules"
    ADD CONSTRAINT "maintenance_schedules_pkey" PRIMARY KEY ("schedule_id");



ALTER TABLE ONLY "public"."notifications"
    ADD CONSTRAINT "notifications_pkey" PRIMARY KEY ("notification_id");



ALTER TABLE ONLY "public"."predictive_maintenance_alerts"
    ADD CONSTRAINT "predictive_maintenance_alerts_pkey" PRIMARY KEY ("alert_id");



ALTER TABLE ONLY "public"."route_deviation_requests"
    ADD CONSTRAINT "route_deviation_requests_pkey" PRIMARY KEY ("request_id");



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_pkey" PRIMARY KEY ("route_id");



ALTER TABLE ONLY "public"."spare_parts"
    ADD CONSTRAINT "spare_parts_pkey" PRIMARY KEY ("part_id");



ALTER TABLE ONLY "public"."trip_issues"
    ADD CONSTRAINT "trip_issues_pkey" PRIMARY KEY ("issue_id");



ALTER TABLE ONLY "public"."trip_logs"
    ADD CONSTRAINT "trip_logs_pkey" PRIMARY KEY ("log_id");



ALTER TABLE ONLY "public"."trips"
    ADD CONSTRAINT "trips_pkey" PRIMARY KEY ("trip_id");



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_pkey" PRIMARY KEY ("assignment_id");



ALTER TABLE ONLY "public"."vehicle_inspections"
    ADD CONSTRAINT "vehicle_inspections_pkey" PRIMARY KEY ("inspection_id");



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_pkey" PRIMARY KEY ("vehicle_id");



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_registration_number_key" UNIQUE ("registration_number");



ALTER TABLE ONLY "public"."work_order_parts"
    ADD CONSTRAINT "work_order_parts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."work_orders"
    ADD CONSTRAINT "work_orders_pkey" PRIMARY KEY ("work_order_id");



CREATE INDEX "idx_assignment_driver" ON "public"."vehicle_assignments" USING "btree" ("driver_id");



CREATE INDEX "idx_assignment_vehicle" ON "public"."vehicle_assignments" USING "btree" ("vehicle_id");



CREATE INDEX "idx_driver_kyc_driver" ON "public"."driver_kyc" USING "btree" ("driver_id");



CREATE INDEX "idx_geofence_event_geofence" ON "public"."geofence_events" USING "btree" ("geofence_id");



CREATE INDEX "idx_geofence_event_trip" ON "public"."geofence_events" USING "btree" ("trip_id");



CREATE INDEX "idx_maintenance_requester" ON "public"."maintenance_requests" USING "btree" ("requested_by");



CREATE INDEX "idx_maintenance_trip" ON "public"."maintenance_requests" USING "btree" ("trip_id");



CREATE INDEX "idx_maintenance_vehicle" ON "public"."maintenance_requests" USING "btree" ("vehicle_id");



CREATE INDEX "idx_predictive_request" ON "public"."predictive_maintenance_alerts" USING "btree" ("maintenance_request_id");



CREATE INDEX "idx_predictive_vehicle" ON "public"."predictive_maintenance_alerts" USING "btree" ("vehicle_id");



CREATE INDEX "idx_record_vehicle" ON "public"."maintenance_records" USING "btree" ("vehicle_id");



CREATE INDEX "idx_record_workorder" ON "public"."maintenance_records" USING "btree" ("work_order_id");



CREATE INDEX "idx_route_request_trip" ON "public"."route_deviation_requests" USING "btree" ("trip_id");



CREATE INDEX "idx_schedule_vehicle" ON "public"."maintenance_schedules" USING "btree" ("vehicle_id");



CREATE INDEX "idx_trip_driver" ON "public"."trips" USING "btree" ("driver_id");



CREATE INDEX "idx_trip_issue_trip" ON "public"."trip_issues" USING "btree" ("trip_id");



CREATE INDEX "idx_trip_logs_trip" ON "public"."trip_logs" USING "btree" ("trip_id");



CREATE INDEX "idx_trip_route" ON "public"."trips" USING "btree" ("route_id");



CREATE INDEX "idx_trip_vehicle" ON "public"."trips" USING "btree" ("vehicle_id");



CREATE INDEX "idx_vehicle_inspection_trip" ON "public"."vehicle_inspections" USING "btree" ("trip_id");



CREATE INDEX "idx_workorder_personnel" ON "public"."work_orders" USING "btree" ("maintenance_personnel_id");



CREATE INDEX "idx_workorder_request" ON "public"."work_orders" USING "btree" ("maintenance_request_id");



CREATE OR REPLACE TRIGGER "set_app_users_updated_at" BEFORE UPDATE ON "public"."app_users" FOR EACH ROW EXECUTE FUNCTION "public"."set_updated_at"();



CREATE OR REPLACE TRIGGER "trg_driver_kyc_updated" BEFORE UPDATE ON "public"."driver_kyc" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_routes_updated" BEFORE UPDATE ON "public"."routes" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_trips_updated" BEFORE UPDATE ON "public"."trips" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_vehicle_assignments_updated" BEFORE UPDATE ON "public"."vehicle_assignments" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "trg_vehicles_updated" BEFORE UPDATE ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



ALTER TABLE ONLY "public"."app_users"
    ADD CONSTRAINT "app_users_admin_owner_id_fkey" FOREIGN KEY ("admin_owner_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."app_users"
    ADD CONSTRAINT "app_users_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fuel_logs"
    ADD CONSTRAINT "fuel_logs_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id");



ALTER TABLE ONLY "public"."fuel_logs"
    ADD CONSTRAINT "fuel_logs_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id");



ALTER TABLE ONLY "public"."geofence_events"
    ADD CONSTRAINT "geofence_events_geofence_id_fkey" FOREIGN KEY ("geofence_id") REFERENCES "public"."geofences"("geofence_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."geofence_events"
    ADD CONSTRAINT "geofence_events_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."inventory_transactions"
    ADD CONSTRAINT "inventory_transactions_part_id_fkey" FOREIGN KEY ("part_id") REFERENCES "public"."spare_parts"("part_id");



ALTER TABLE ONLY "public"."inventory_transactions"
    ADD CONSTRAINT "inventory_transactions_work_order_id_fkey" FOREIGN KEY ("work_order_id") REFERENCES "public"."work_orders"("work_order_id");



ALTER TABLE ONLY "public"."maintenance_records"
    ADD CONSTRAINT "maintenance_records_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."maintenance_records"
    ADD CONSTRAINT "maintenance_records_work_order_id_fkey" FOREIGN KEY ("work_order_id") REFERENCES "public"."work_orders"("work_order_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."maintenance_requests"
    ADD CONSTRAINT "maintenance_requests_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."maintenance_requests"
    ADD CONSTRAINT "maintenance_requests_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."maintenance_schedules"
    ADD CONSTRAINT "maintenance_schedules_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."predictive_maintenance_alerts"
    ADD CONSTRAINT "predictive_maintenance_alerts_maintenance_request_id_fkey" FOREIGN KEY ("maintenance_request_id") REFERENCES "public"."maintenance_requests"("request_id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."predictive_maintenance_alerts"
    ADD CONSTRAINT "predictive_maintenance_alerts_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."route_deviation_requests"
    ADD CONSTRAINT "route_deviation_requests_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trip_issues"
    ADD CONSTRAINT "trip_issues_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trip_logs"
    ADD CONSTRAINT "trip_logs_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trips"
    ADD CONSTRAINT "trips_route_id_fkey" FOREIGN KEY ("route_id") REFERENCES "public"."routes"("route_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."trips"
    ADD CONSTRAINT "trips_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id") ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."vehicle_assignments"
    ADD CONSTRAINT "vehicle_assignments_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("vehicle_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_inspections"
    ADD CONSTRAINT "vehicle_inspections_trip_id_fkey" FOREIGN KEY ("trip_id") REFERENCES "public"."trips"("trip_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."work_order_parts"
    ADD CONSTRAINT "work_order_parts_part_id_fkey" FOREIGN KEY ("part_id") REFERENCES "public"."spare_parts"("part_id");



ALTER TABLE ONLY "public"."work_order_parts"
    ADD CONSTRAINT "work_order_parts_work_order_id_fkey" FOREIGN KEY ("work_order_id") REFERENCES "public"."work_orders"("work_order_id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."work_orders"
    ADD CONSTRAINT "work_orders_maintenance_request_id_fkey" FOREIGN KEY ("maintenance_request_id") REFERENCES "public"."maintenance_requests"("request_id") ON DELETE CASCADE;



CREATE POLICY "Admins can create owned users" ON "public"."app_users" FOR INSERT WITH CHECK (("public"."is_current_user_admin"() AND ("admin_owner_id" = "public"."current_user_admin_owner_id"()) AND ("role" <> 'admin'::"public"."user_role")));



CREATE POLICY "Admins can read owned users" ON "public"."app_users" FOR SELECT USING (("public"."is_current_user_admin"() AND ("admin_owner_id" = "public"."current_user_admin_owner_id"())));



CREATE POLICY "Admins can self register" ON "public"."app_users" FOR INSERT WITH CHECK ((("user_id" = "auth"."uid"()) AND ("admin_owner_id" = "auth"."uid"()) AND ("role" = 'admin'::"public"."user_role")));



CREATE POLICY "Admins can update owned users" ON "public"."app_users" FOR UPDATE USING (("public"."is_current_user_admin"() AND ("admin_owner_id" = "public"."current_user_admin_owner_id"()))) WITH CHECK (("public"."is_current_user_admin"() AND ("admin_owner_id" = "public"."current_user_admin_owner_id"())));



CREATE POLICY "Users can read own profile" ON "public"."app_users" FOR SELECT USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."app_users" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."driver_kyc" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."fuel_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."geofence_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."geofences" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."inventory_transactions" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."maintenance_records" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."maintenance_requests" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."maintenance_schedules" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."notifications" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."predictive_maintenance_alerts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."route_deviation_requests" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."routes" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."spare_parts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."trip_issues" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."trip_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."trips" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicle_assignments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicle_inspections" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."work_order_parts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."work_orders" ENABLE ROW LEVEL SECURITY;


GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";



GRANT ALL ON FUNCTION "public"."admin_create_user"("p_email" "text", "p_password" "text", "p_role" "text", "p_full_name" "text", "p_phone" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."admin_create_user"("p_email" "text", "p_password" "text", "p_role" "text", "p_full_name" "text", "p_phone" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."admin_create_user"("p_email" "text", "p_password" "text", "p_role" "text", "p_full_name" "text", "p_phone" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_user_exists_by_email"("lookup_email" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."check_user_exists_by_email"("lookup_email" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_user_exists_by_email"("lookup_email" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."current_user_admin_owner_id"() TO "anon";
GRANT ALL ON FUNCTION "public"."current_user_admin_owner_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."current_user_admin_owner_id"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "service_role";



GRANT ALL ON FUNCTION "public"."is_current_user_admin"() TO "anon";
GRANT ALL ON FUNCTION "public"."is_current_user_admin"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_current_user_admin"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "service_role";



GRANT ALL ON TABLE "public"."app_users" TO "anon";
GRANT ALL ON TABLE "public"."app_users" TO "authenticated";
GRANT ALL ON TABLE "public"."app_users" TO "service_role";



GRANT ALL ON TABLE "public"."driver_kyc" TO "anon";
GRANT ALL ON TABLE "public"."driver_kyc" TO "authenticated";
GRANT ALL ON TABLE "public"."driver_kyc" TO "service_role";



GRANT ALL ON SEQUENCE "public"."driver_kyc_kyc_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."driver_kyc_kyc_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."driver_kyc_kyc_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."fuel_logs" TO "anon";
GRANT ALL ON TABLE "public"."fuel_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."fuel_logs" TO "service_role";



GRANT ALL ON SEQUENCE "public"."fuel_logs_fuel_log_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."fuel_logs_fuel_log_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."fuel_logs_fuel_log_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."geofence_events" TO "anon";
GRANT ALL ON TABLE "public"."geofence_events" TO "authenticated";
GRANT ALL ON TABLE "public"."geofence_events" TO "service_role";



GRANT ALL ON SEQUENCE "public"."geofence_events_event_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."geofence_events_event_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."geofence_events_event_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."geofences" TO "anon";
GRANT ALL ON TABLE "public"."geofences" TO "authenticated";
GRANT ALL ON TABLE "public"."geofences" TO "service_role";



GRANT ALL ON SEQUENCE "public"."geofences_geofence_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."geofences_geofence_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."geofences_geofence_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."inventory_transactions" TO "anon";
GRANT ALL ON TABLE "public"."inventory_transactions" TO "authenticated";
GRANT ALL ON TABLE "public"."inventory_transactions" TO "service_role";



GRANT ALL ON SEQUENCE "public"."inventory_transactions_transaction_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."inventory_transactions_transaction_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."inventory_transactions_transaction_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."maintenance_records" TO "anon";
GRANT ALL ON TABLE "public"."maintenance_records" TO "authenticated";
GRANT ALL ON TABLE "public"."maintenance_records" TO "service_role";



GRANT ALL ON SEQUENCE "public"."maintenance_records_record_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."maintenance_records_record_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."maintenance_records_record_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."maintenance_requests" TO "anon";
GRANT ALL ON TABLE "public"."maintenance_requests" TO "authenticated";
GRANT ALL ON TABLE "public"."maintenance_requests" TO "service_role";



GRANT ALL ON SEQUENCE "public"."maintenance_requests_request_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."maintenance_requests_request_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."maintenance_requests_request_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."maintenance_schedules" TO "anon";
GRANT ALL ON TABLE "public"."maintenance_schedules" TO "authenticated";
GRANT ALL ON TABLE "public"."maintenance_schedules" TO "service_role";



GRANT ALL ON SEQUENCE "public"."maintenance_schedules_schedule_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."maintenance_schedules_schedule_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."maintenance_schedules_schedule_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."notifications" TO "anon";
GRANT ALL ON TABLE "public"."notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."notifications" TO "service_role";



GRANT ALL ON SEQUENCE "public"."notifications_notification_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."notifications_notification_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."notifications_notification_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."predictive_maintenance_alerts" TO "anon";
GRANT ALL ON TABLE "public"."predictive_maintenance_alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."predictive_maintenance_alerts" TO "service_role";



GRANT ALL ON SEQUENCE "public"."predictive_maintenance_alerts_alert_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."predictive_maintenance_alerts_alert_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."predictive_maintenance_alerts_alert_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."route_deviation_requests" TO "anon";
GRANT ALL ON TABLE "public"."route_deviation_requests" TO "authenticated";
GRANT ALL ON TABLE "public"."route_deviation_requests" TO "service_role";



GRANT ALL ON SEQUENCE "public"."route_deviation_requests_request_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."route_deviation_requests_request_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."route_deviation_requests_request_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."routes" TO "anon";
GRANT ALL ON TABLE "public"."routes" TO "authenticated";
GRANT ALL ON TABLE "public"."routes" TO "service_role";



GRANT ALL ON SEQUENCE "public"."routes_route_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."routes_route_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."routes_route_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."spare_parts" TO "anon";
GRANT ALL ON TABLE "public"."spare_parts" TO "authenticated";
GRANT ALL ON TABLE "public"."spare_parts" TO "service_role";



GRANT ALL ON SEQUENCE "public"."spare_parts_part_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."spare_parts_part_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."spare_parts_part_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."trip_issues" TO "anon";
GRANT ALL ON TABLE "public"."trip_issues" TO "authenticated";
GRANT ALL ON TABLE "public"."trip_issues" TO "service_role";



GRANT ALL ON SEQUENCE "public"."trip_issues_issue_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."trip_issues_issue_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."trip_issues_issue_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."trip_logs" TO "anon";
GRANT ALL ON TABLE "public"."trip_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."trip_logs" TO "service_role";



GRANT ALL ON SEQUENCE "public"."trip_logs_log_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."trip_logs_log_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."trip_logs_log_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."trips" TO "anon";
GRANT ALL ON TABLE "public"."trips" TO "authenticated";
GRANT ALL ON TABLE "public"."trips" TO "service_role";



GRANT ALL ON SEQUENCE "public"."trips_trip_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."trips_trip_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."trips_trip_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."vehicle_assignments" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_assignments" TO "service_role";



GRANT ALL ON SEQUENCE "public"."vehicle_assignments_assignment_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."vehicle_assignments_assignment_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."vehicle_assignments_assignment_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."vehicle_inspections" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_inspections" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_inspections" TO "service_role";



GRANT ALL ON SEQUENCE "public"."vehicle_inspections_inspection_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."vehicle_inspections_inspection_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."vehicle_inspections_inspection_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."vehicles" TO "anon";
GRANT ALL ON TABLE "public"."vehicles" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicles" TO "service_role";



GRANT ALL ON SEQUENCE "public"."vehicles_vehicle_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."vehicles_vehicle_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."vehicles_vehicle_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."work_order_parts" TO "anon";
GRANT ALL ON TABLE "public"."work_order_parts" TO "authenticated";
GRANT ALL ON TABLE "public"."work_order_parts" TO "service_role";



GRANT ALL ON SEQUENCE "public"."work_order_parts_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."work_order_parts_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."work_order_parts_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."work_orders" TO "anon";
GRANT ALL ON TABLE "public"."work_orders" TO "authenticated";
GRANT ALL ON TABLE "public"."work_orders" TO "service_role";



GRANT ALL ON SEQUENCE "public"."work_orders_work_order_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."work_orders_work_order_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."work_orders_work_order_id_seq" TO "service_role";



ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";







