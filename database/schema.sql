--
-- PostgreSQL database dump
--

\restrict kpGJfflE4q2Qna7PqcZj6CO8OK6cwgtTJT1S1Pi64Z5Dvt0wRtw1sqFWR6p0sBt

-- Dumped from database version 14.23 (Ubuntu 14.23-0ubuntu0.22.04.1)
-- Dumped by pg_dump version 14.23 (Ubuntu 14.23-0ubuntu0.22.04.1)

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cases (
    id integer NOT NULL,
    case_id character varying(100),
    title text,
    severity character varying(20),
    status character varying(20) DEFAULT 'open'::character varying,
    mitre_tactic character varying(100),
    mitre_technique character varying(100),
    affected_assets text[],
    alert_ids text[],
    fp_probability double precision,
    remediation text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: cases_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cases_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cases_id_seq OWNED BY public.cases.id;


--
-- Name: enriched_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enriched_alerts (
    id integer NOT NULL,
    alert_id character varying(100),
    "timestamp" timestamp with time zone,
    agent_name character varying(100),
    agent_ip character varying(50),
    rule_id integer,
    rule_description text,
    rule_level integer,
    src_ip character varying(50),
    dst_ip character varying(50),
    src_port integer,
    dst_port integer,
    protocol character varying(20),
    country character varying(100),
    city character varying(100),
    latitude double precision,
    longitude double precision,
    abuse_score integer,
    cvss_score double precision,
    risk_score double precision,
    mitre_tactic character varying(100),
    mitre_technique character varying(100),
    is_duplicate boolean DEFAULT false,
    is_noise boolean DEFAULT false,
    raw_alert jsonb,
    created_at timestamp with time zone DEFAULT now(),
    is_processed boolean DEFAULT false
);


--
-- Name: enriched_alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.enriched_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: enriched_alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.enriched_alerts_id_seq OWNED BY public.enriched_alerts.id;


--
-- Name: feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feedback (
    id integer NOT NULL,
    case_id character varying(100),
    alert_id character varying(100),
    label character varying(20),
    analyst character varying(100),
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: feedback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.feedback_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: feedback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.feedback_id_seq OWNED BY public.feedback.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(150),
    role character varying(50) DEFAULT 'analyst'::character varying,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: cases id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases ALTER COLUMN id SET DEFAULT nextval('public.cases_id_seq'::regclass);


--
-- Name: enriched_alerts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enriched_alerts ALTER COLUMN id SET DEFAULT nextval('public.enriched_alerts_id_seq'::regclass);


--
-- Name: feedback id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback ALTER COLUMN id SET DEFAULT nextval('public.feedback_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: cases cases_case_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_case_id_key UNIQUE (case_id);


--
-- Name: cases cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (id);


--
-- Name: enriched_alerts enriched_alerts_alert_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enriched_alerts
    ADD CONSTRAINT enriched_alerts_alert_id_key UNIQUE (alert_id);


--
-- Name: enriched_alerts enriched_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enriched_alerts
    ADD CONSTRAINT enriched_alerts_pkey PRIMARY KEY (id);


--
-- Name: feedback feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback
    ADD CONSTRAINT feedback_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_alerts_created_processed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_created_processed ON public.enriched_alerts USING btree (created_at, is_processed);


--
-- Name: idx_alerts_src_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_src_ip ON public.enriched_alerts USING btree (src_ip, created_at);


--
-- PostgreSQL database dump complete
--

\unrestrict kpGJfflE4q2Qna7PqcZj6CO8OK6cwgtTJT1S1Pi64Z5Dvt0wRtw1sqFWR6p0sBt

